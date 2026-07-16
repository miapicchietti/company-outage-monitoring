#!/usr/bin/env python3
"""Synthetic monitoring: times each company's homepage and alerts to Slack."""

import base64
import csv
import fcntl
import html
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import urllib3.util.connection as urllib3_cn

# This network has a broken/blackholed IPv6 route: any connection attempt
# (direct or the OS cert-verification calls truststore triggers) stalls for
# 10s+ on IPv6 before falling back to IPv4. Forcing IPv4 everywhere avoids it.
urllib3_cn.allowed_gai_family = lambda: socket.AF_INET

import truststore

truststore.inject_into_ssl()

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
COMPANIES_CSV_PATH = os.path.join(BASE_DIR, "companies.csv")
CSV_LOG_PATH = os.path.join(BASE_DIR, "monitor_log.csv")
SLOW_TRICKLE_LOG_PATH = os.path.join(BASE_DIR, "slow_trickle_log.csv")
STATE_PATH = os.path.join(BASE_DIR, "state.json")
LOCK_PATH = os.path.join(BASE_DIR, "monitor.lock")
STATUS_PAGE_PATH = os.path.join(BASE_DIR, "status.html")
PAGES_WORKTREE_PATH = os.path.join(BASE_DIR, ".pages-worktree")
LAST_DEPLOY_PATH = os.path.join(BASE_DIR, ".last_deploy")
MIN_DEPLOY_INTERVAL_SECONDS = 60
CSV_FIELDS = [
    "timestamp",
    "url",
    "http_status",
    "response_time_s",
    "slow",
    "claude_status",
    "claude_analysis",
]

# Tiled overlapping-circle background pattern for the dashboard: varied circle
# sizes in one repeating 760x760 tile, mirrored across edges so it tiles
# seamlessly, with enough gap between circles for the cream wash to show through.
_BG_PATTERN_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="760" height="760">
<circle cx="0" cy="0" r="220" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="760" cy="0" r="220" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="0" cy="760" r="220" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="760" cy="760" r="220" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="0" cy="400" r="200" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="760" cy="400" r="200" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="250" cy="0" r="180" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="250" cy="760" r="180" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="560" cy="0" r="160" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="560" cy="760" r="160" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="420" cy="300" r="240" fill="#ffffff" fill-opacity="0.6"/>
<circle cx="180" cy="550" r="190" fill="#ffffff" fill-opacity="0.6"/>
</svg>"""
BG_PATTERN_B64 = base64.b64encode(_BG_PATTERN_SVG.encode()).decode()


def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state):
    with open(STATE_PATH, "w") as f:
        json.dump(state, f)


def is_outage(result):
    return (
        result["error"] is not None
        or result["status_code"] is None
        or (result["status_code"] is not None and result["status_code"] >= 500)
        or result["status_code"] == 404
    )


def get_previous_alert_state(state, company):
    entry = state.get(company)
    if isinstance(entry, dict):
        return entry.get("breached", False), entry.get("consecutive_fails", 0)
    return bool(entry), 0


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def load_companies():
    with open(COMPANIES_CSV_PATH, newline="") as f:
        return [(row["company"], row["url"]) for row in csv.DictReader(f)]


_slow_trickle_lock = threading.Lock()


def log_slow_trickle(company, url, true_elapsed, status_code, error):
    """Diagnostic-only: records how long a request that blew past the hard
    timeout actually took to finish. Never affects the live monitoring verdict
    -- it's purely for picking a well-informed http_timeout_seconds later."""
    row = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "company": company or "",
        "url": url,
        "true_elapsed_s": f"{true_elapsed:.3f}",
        "final_status": status_code if status_code is not None else "",
        "final_error": error or "",
    }
    with _slow_trickle_lock:
        file_exists = os.path.exists(SLOW_TRICKLE_LOG_PATH)
        with open(SLOW_TRICKLE_LOG_PATH, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(row.keys()))
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)


def _classify_connection_error(e):
    text = str(e)
    if "NameResolutionError" in text or "nodename nor servname" in text or "Name or service not known" in text:
        return "Connection Error: DNS Resolution Failed"
    if "Connection refused" in text:
        return "Connection Error: Connection Refused"
    if "Connection reset" in text or "ConnectionResetError" in text:
        return "Connection Error: Connection Reset"
    if "EOF occurred" in text or "Connection aborted" in text:
        return "Connection Error: Connection Aborted"
    return "Connection Error"


def _do_get(url, timeout, result_holder):
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                )
            },
            allow_redirects=True,
        )
        result_holder["status_code"] = resp.status_code
        result_holder["error"] = None
    except requests.exceptions.Timeout:
        result_holder["status_code"] = None
        result_holder["error"] = "Timeout"
    except requests.exceptions.SSLError as e:
        result_holder["status_code"] = None
        result_holder["error"] = f"SSL Error: {str(e)[:80]}"
    except requests.exceptions.ConnectionError as e:
        result_holder["status_code"] = None
        result_holder["error"] = _classify_connection_error(e)
    except requests.exceptions.RequestException as e:
        result_holder["status_code"] = None
        result_holder["error"] = type(e).__name__
    finally:
        result_holder["finished_at"] = datetime.now()


def check_url(url, timeout, company=None):
    # requests' own timeout= is a per-read timeout, not a total-duration one --
    # a server that trickles bytes slowly can dodge it and hang far past
    # `timeout`. thread.join(timeout=...) below is the actual hard wall-clock
    # cap: it returns control after `timeout` seconds no matter what the
    # request thread is doing. The request thread is daemonized so an
    # abandoned one can't block the script from exiting.
    start = datetime.now()
    result_holder = {}
    thread = threading.Thread(target=_do_get, args=(url, timeout, result_holder), daemon=True)
    thread.start()
    thread.join(timeout=timeout)
    elapsed = (datetime.now() - start).total_seconds()

    if thread.is_alive():
        def _log_true_completion():
            thread.join()
            true_elapsed = (result_holder.get("finished_at", datetime.now()) - start).total_seconds()
            log_slow_trickle(
                company, url, true_elapsed,
                result_holder.get("status_code"), result_holder.get("error"),
            )

        threading.Thread(target=_log_true_completion, daemon=True).start()
        return {"elapsed": elapsed, "status_code": None, "error": "Timeout"}

    return {
        "elapsed": elapsed,
        "status_code": result_holder.get("status_code"),
        "error": result_holder.get("error"),
    }


def browser_verify(url, timeout_seconds):
    """Only called to double-check a confirmed 'Timeout' or 'Connection Error'
    from check_url(). Loads the URL in an actual headless Chromium, the same
    way a real visitor's browser would -- if it loads fine here, the plain
    HTTP client's failure was a false positive (e.g. a quirk in its
    connection handling that a real browser's networking stack doesn't hit)."""
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            try:
                response = page.goto(url, timeout=timeout_seconds * 1000)
                status = response.status if response else None
                browser.close()
                return {"loaded": True, "status_code": status, "error": None}
            except Exception as e:
                browser.close()
                return {"loaded": False, "status_code": None, "error": f"{type(e).__name__}: {str(e)[:150]}"}
    except Exception as e:
        return {"loaded": False, "status_code": None, "error": f"{type(e).__name__}: {str(e)[:150]}"}


def log_result(row):
    file_exists = os.path.exists(CSV_LOG_PATH)
    with open(CSV_LOG_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def fallback_reason(check_result, threshold):
    if check_result["error"]:
        return check_result["error"]
    if check_result["status_code"] and check_result["status_code"] >= 500:
        return f"HTTP {check_result['status_code']} Server Error"
    if check_result["status_code"] and check_result["status_code"] >= 400:
        return f"HTTP {check_result['status_code']} Client Error"
    if check_result["elapsed"] > threshold:
        return f"Slow response ({check_result['elapsed']:.2f}s)"
    return "Unknown"


def send_slack_alert(webhook_url, company, url, reason, is_down, elapsed, threshold):
    status_phrase = "is down" if is_down else "is responding slowly"
    emoji = ":red_circle:" if is_down else ":turtle:"
    text = (
        f"{emoji} {company} {status_phrase}\n"
        f"{url}\n"
        f"Response time: {elapsed:.2f}s (threshold: {threshold:.2f}s) | Reason: {reason}"
    )
    try:
        requests.post(webhook_url, json={"text": text}, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"  Failed to send Slack alert: {e}")


def format_down_duration(down_since):
    if not down_since:
        return ""
    try:
        started = datetime.strptime(down_since, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ""
    seconds = max(0, (datetime.now() - started).total_seconds())
    minutes = int(seconds // 60)
    if minutes < 1:
        return "<1m"
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _company_stats_text(entry):
    total_checks = entry.get("total_checks", 0)
    outage_count = entry.get("outage_count", 0)
    response_time_sum = entry.get("response_time_sum", 0.0)
    if not total_checks:
        return None
    avg_response = response_time_sum / total_checks
    return f"Checked {total_checks}x | Down {outage_count}x | Avg response {avg_response:.2f}s"


def _status_row(company, url, state_label, down_since=None, reason=None, stats_text=None, show_status=True, show_duration=True):
    company_esc = html.escape(company)
    url_esc = html.escape(url, quote=True)
    label = {"outage": "Down", "slow": "Slow", "ok": "OK"}[state_label]
    duration = format_down_duration(down_since) if state_label != "ok" else ""

    detail_lines = []
    if state_label == "outage" and reason:
        detail_lines.append(html.escape(reason))
    if stats_text:
        detail_lines.append(html.escape(stats_text))

    if detail_lines:
        detail_html = "".join(f"<div class='reason-line'>{line}</div>" for line in detail_lines)
        name_html = (
            f"<span class='reason-details'>"
            f"<span class='reason-name'>{company_esc}</span>"
            f"<span class='reason-box'>{detail_html}</span>"
            f"</span>"
        )
    else:
        name_html = company_esc

    status_cell = f"<td><span class='pill pill-{state_label}'>{label}</span></td>" if show_status else ""
    duration_cell = f"<td class='duration'>{duration}</td>" if show_duration else ""
    return (
        f"<tr class='{state_label}' data-name='{company_esc.lower()}'>"
        f"<td>{name_html}</td>"
        f"<td><a href='{url_esc}'>{url_esc}</a></td>"
        f"{status_cell}"
        f"{duration_cell}"
        f"</tr>\n"
    )


def generate_status_page(companies, state):
    outages = []
    slow = []
    ok = []
    for company, url in companies:
        entry = state.get(company, {})
        stats_text = _company_stats_text(entry) if isinstance(entry, dict) else None
        if isinstance(entry, dict) and entry.get("breached"):
            down_since = entry.get("down_since")
            if entry.get("is_outage", True):
                outages.append((company, url, down_since, entry.get("reason"), stats_text))
            else:
                slow.append((company, url, down_since, stats_text))
        else:
            ok.append((company, url, stats_text))

    total = len(outages) + len(slow) + len(ok)
    generated_at = datetime.now().astimezone().strftime("%-I:%M %p %Z")

    if outages:
        outage_html = "".join(
            _status_row(c, u, "outage", ds, r, st, show_status=False) for c, u, ds, r, st in outages
        )
    else:
        outage_html = (
            "<tr><td colspan='3' class='empty'>No outages right now.</td></tr>\n"
        )

    if slow:
        slow_html = "".join(
            _status_row(c, u, "slow", ds, None, st, show_status=False, show_duration=False)
            for c, u, ds, st in slow
        )
    else:
        slow_html = (
            "<tr><td colspan='2' class='empty'>Nothing running slow right now.</td></tr>\n"
        )

    all_rows_html = (
        "".join(_status_row(c, u, "outage", ds, r, st) for c, u, ds, r, st in outages)
        + "".join(_status_row(c, u, "slow", ds, None, st) for c, u, ds, st in slow)
        + "".join(_status_row(c, u, "ok", None, None, st) for c, u, st in ok)
    )

    page = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Synthetic Monitor Status</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,600;0,9..144,700;1,9..144,500&display=swap" rel="stylesheet">
<style>
  :root {{
    --surface-1: #ffffff;
    --page-plane: #faf8f6;
    --text-primary: #1a1a1a;
    --text-secondary: #5c5c5c;
    --text-muted: #8a8a8a;
    --gridline: #e5e3e0;
    --border: rgba(26,26,26,0.10);
    --brand-accent: #d2775a;
    --status-good: #0ca30c;
    --status-warning: #fab219;
    --status-critical: #d03b3b;
    --font-display: 'Fraunces', Georgia, serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    background-color: var(--page-plane);
    background-image:
      url("data:image/svg+xml;base64,{BG_PATTERN_B64}"),
      linear-gradient(135deg, #efd8c1 0%, #f7f4ef 45%, #f3d5c2 100%);
    background-size: 760px 760px, cover;
    background-attachment: fixed, fixed;
    color: var(--text-primary);
    margin: 0;
    padding: 0 0 4rem;
  }}
  .topnav {{ max-width: 880px; margin: 0 auto; padding: 1.5rem 1.5rem 0; display: flex; align-items: center; justify-content: space-between; }}
  .wordmark {{ font-family: var(--font-display); font-style: italic; font-weight: 600; font-size: 1.2rem; color: var(--text-primary); }}
  .nav-pill {{
    font-size: 0.8rem; font-weight: 600; color: var(--text-primary);
    background: var(--surface-1); border: 1px solid var(--border);
    padding: 0.4rem 0.95rem; border-radius: 999px; text-decoration: none;
  }}
  .nav-pill:hover {{ border-color: var(--brand-accent); color: var(--brand-accent); }}
  .header-band {{
    background: linear-gradient(135deg, #c26a4d, #dc8a6c);
    box-shadow: 0 16px 36px rgba(194,106,77,0.28);
    padding: 2.5rem 2rem; width: calc(100% - 0.5rem); max-width: 880px;
    margin: 1.5rem auto 2rem; border-radius: 20px;
  }}
  .header-inner {{ max-width: 880px; margin: 0 auto; padding: 0; }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 0 1.5rem; }}
  .eyebrow {{
    display: inline-block; background: rgba(26,26,26,0.82); color: #faf8f6;
    font-size: 0.68rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.08em; padding: 0.32rem 0.75rem; border-radius: 999px;
    margin-bottom: 0.9rem;
  }}
  h1 {{
    font-family: var(--font-display); font-size: 2.5rem; font-weight: 700;
    line-height: 1.04; margin: 0 0 0.4rem; color: #1a1a1a; letter-spacing: -0.01em;
  }}
  .meta {{ color: rgba(26,26,26,0.65); font-size: 0.88rem; margin: 0; }}
  .tiles {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 2rem; }}
  .tile {{
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 14px;
    box-shadow: 0 1px 2px rgba(26,26,26,0.04), 0 8px 20px rgba(26,26,26,0.05);
    padding: 1rem 1.1rem;
  }}
  .tile .label {{ font-size: 0.78rem; color: var(--text-secondary); margin-bottom: 0.3rem; }}
  .tile .value {{ font-size: 2rem; font-weight: 600; line-height: 1; color: var(--text-primary); }}
  .tile.slow {{ border-left: 3px solid var(--status-warning); }}
  section {{ margin-bottom: 2rem; }}
  h2 {{ font-size: 0.95rem; font-weight: 600; margin: 0 0 0.75rem; }}
  table {{ border-collapse: collapse; width: 100%; background: var(--surface-1); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; box-shadow: 0 1px 2px rgba(26,26,26,0.04), 0 8px 20px rgba(26,26,26,0.05); }}
  th {{ text-align: left; font-size: 0.75rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em; padding: 0.6rem 0.9rem; border-bottom: 1px solid var(--gridline); }}
  td {{ text-align: left; padding: 0.55rem 0.9rem; border-bottom: 1px solid var(--gridline); font-size: 0.9rem; }}
  tr:last-child td {{ border-bottom: none; }}
  td a {{ color: var(--text-secondary); text-decoration: none; }}
  td a:hover {{ color: var(--brand-accent); text-decoration: underline; }}
  td.duration {{ color: var(--text-secondary); font-variant-numeric: tabular-nums; white-space: nowrap; }}
  .empty {{ color: var(--text-muted); text-align: center; padding: 1.5rem; }}
  .pill {{
    display: inline-flex; align-items: center; font-size: 0.72rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.03em; padding: 0.22rem 0.65rem;
    border-radius: 999px;
  }}
  .pill-outage {{ color: var(--status-critical); background: rgba(208,59,59,0.12); }}
  .pill-slow {{ color: #8a5a00; background: rgba(250,178,25,0.18); }}
  .pill-ok {{ color: var(--status-good); background: rgba(12,163,12,0.12); }}
  input[type="search"] {{
    width: 100%; padding: 0.6rem 1.05rem; margin-bottom: 0.75rem;
    border: 1px solid var(--border); border-radius: 999px;
    background: var(--surface-1); color: var(--text-primary); font-size: 0.9rem;
  }}
  input[type="search"]:focus {{ outline: none; border-color: var(--brand-accent); }}
  details summary {{ cursor: pointer; font-size: 0.95rem; font-weight: 600; padding: 0.4rem 0; display: flex; align-items: center; gap: 0.55rem; }}
  .count-chip {{
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 1.5rem; padding: 0.1rem 0.5rem; border-radius: 999px;
    font-size: 0.75rem; font-weight: 700; font-variant-numeric: tabular-nums;
    background: rgba(26,26,26,0.07); color: var(--text-secondary);
  }}
  .count-chip.outage {{ background: rgba(208,59,59,0.12); color: var(--status-critical); }}
  .count-chip.slow {{ background: rgba(250,178,25,0.18); color: #8a5a00; }}
  tr.js-hidden {{ display: none; }}
  .reason-details {{ position: relative; }}
  .reason-details .reason-name {{ cursor: default; }}
  .reason-details:hover .reason-name {{ text-decoration: underline dotted; }}
  .reason-details .reason-box {{
    display: none;
    position: absolute;
    left: calc(100% + 0.6rem);
    top: 50%;
    transform: translateY(-50%);
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    box-shadow: 0 6px 20px rgba(0,0,0,0.2);
    white-space: nowrap;
    z-index: 20;
  }}
  .reason-details:hover .reason-box {{
    display: block;
  }}
  .reason-details .reason-line {{
    display: block;
    font-size: 0.8rem; font-weight: 400; color: var(--text-secondary);
  }}
  .reason-details .reason-line + .reason-line {{ margin-top: 0.3rem; }}
</style>
</head>
<body>
<div class="topnav">
  <span class="wordmark">Synthetic Monitor</span>
  <a class="nav-pill" href="https://github.com/miapicchietti/company-outage-monitoring" target="_blank" rel="noopener">View source</a>
</div>
<div class="header-band">
  <div class="header-inner">
    <span class="eyebrow">Automated &middot; every 5 min</span>
    <h1>Synthetic Monitor<br><span class="accent">Status</span></h1>
    <p class="meta">Last updated: {generated_at}</p>
  </div>
</div>
<div class="wrap">
  <div class="tiles">
    <div class="tile outage">
      <div class="label">Outages</div>
      <div class="value">{len(outages)}</div>
    </div>
    <div class="tile slow">
      <div class="label">Slow</div>
      <div class="value">{len(slow)}</div>
    </div>
    <div class="tile ok">
      <div class="label">Healthy</div>
      <div class="value">{len(ok)}</div>
    </div>
    <div class="tile">
      <div class="label">Total monitored</div>
      <div class="value">{total}</div>
    </div>
  </div>

  <section>
    <details open>
      <summary>Outages <span class="count-chip outage">{len(outages)}</span></summary>
      <table style="margin-top: 0.75rem;">
        <tr><th>Company</th><th>URL</th><th>Down for</th></tr>
        {outage_html}
      </table>
    </details>
  </section>

  <section>
    <details open>
      <summary>Slow <span class="count-chip slow">{len(slow)}</span></summary>
      <table style="margin-top: 0.75rem;">
        <tr><th>Company</th><th>URL</th></tr>
        {slow_html}
      </table>
    </details>
  </section>

  <section>
    <details>
      <summary>All monitored companies <span class="count-chip">{total}</span></summary>
      <div style="margin-top: 0.85rem;">
        <input type="search" id="filter" placeholder="Filter by company name&hellip;">
        <table id="all-table">
          <tr><th>Company</th><th>URL</th><th>Status</th><th>Down for</th></tr>
          {all_rows_html}
        </table>
      </div>
    </details>
  </section>
</div>
<script>
  document.getElementById('filter').addEventListener('input', function (e) {{
    var q = e.target.value.trim().toLowerCase();
    var rows = document.querySelectorAll('#all-table tr[data-name]');
    rows.forEach(function (row) {{
      row.classList.toggle('js-hidden', q.length > 0 && row.dataset.name.indexOf(q) === -1);
    }});
  }});
</script>
</body>
</html>
"""
    with open(STATUS_PAGE_PATH, "w") as f:
        f.write(page)


def deploy_status_page():
    if not os.path.isdir(PAGES_WORKTREE_PATH):
        return

    now = datetime.now()
    try:
        with open(LAST_DEPLOY_PATH) as f:
            last = datetime.strptime(f.read().strip(), "%Y-%m-%d %H:%M:%S")
        if (now - last).total_seconds() < MIN_DEPLOY_INTERVAL_SECONDS:
            return
    except (FileNotFoundError, ValueError):
        pass

    shutil.copyfile(STATUS_PAGE_PATH, os.path.join(PAGES_WORKTREE_PATH, "index.html"))

    status = subprocess.run(
        ["git", "-C", PAGES_WORKTREE_PATH, "status", "--porcelain"],
        capture_output=True, text=True,
    )
    if not status.stdout.strip():
        return

    try:
        subprocess.run(
            ["git", "-C", PAGES_WORKTREE_PATH, "add", "index.html"],
            check=True, capture_output=True, timeout=15,
        )
        subprocess.run(
            ["git", "-C", PAGES_WORKTREE_PATH, "commit", "-m", f"Update status page {now.strftime('%Y-%m-%d %H:%M:%S')}"],
            check=True, capture_output=True, timeout=15,
        )
        subprocess.run(
            ["git", "-C", PAGES_WORKTREE_PATH, "push"],
            check=True, capture_output=True, timeout=30,
        )
        with open(LAST_DEPLOY_PATH, "w") as f:
            f.write(now.strftime("%Y-%m-%d %H:%M:%S"))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"  Failed to deploy status page: {e}")


def run_company_check(company, url, http_timeout):
    """Runs entirely off shared state -- safe to call concurrently from a
    thread pool. Does the actual check plus any Timeout/Connection Error
    verification, and returns the result plus any diagnostic lines to print.
    All state/log/Slack/deploy handling happens back on the main thread."""
    log_lines = []
    result = check_url(url, http_timeout, company)
    if result["error"] == "Timeout":
        time.sleep(30)
        result = check_url(url, http_timeout, company)
    if result["error"] == "Timeout" or (result["error"] and result["error"].startswith("Connection Error")):
        browser_result = browser_verify(url, http_timeout)
        if browser_result["loaded"]:
            # A real browser loaded it fine -- the HTTP client's failure
            # was a false positive, not a genuine outage.
            result = {
                "elapsed": result["elapsed"],
                "status_code": browser_result["status_code"],
                "error": None,
            }
        else:
            log_lines.append(f"  Playwright verification also failed for {company}: {browser_result['error']}")
    return result, log_lines


def main():
    config = load_config()
    threshold = config["threshold_seconds"]
    http_timeout = config["http_timeout_seconds"]
    webhook_url = os.environ["SLACK_WEBHOOK_URL"]
    consecutive_failures_required = config.get("consecutive_failures_required", 2)
    alert_on_slow = config.get("alert_on_slow", True)
    max_concurrent_checks = config.get("max_concurrent_checks", 1)
    state = load_state()
    companies = load_companies()

    with ThreadPoolExecutor(max_workers=max_concurrent_checks) as executor:
        futures = {
            executor.submit(run_company_check, company, url, http_timeout): (company, url)
            for company, url in companies
        }
        for future in as_completed(futures):
            company, url = futures[future]
            try:
                result, log_lines = future.result()
            except Exception as e:
                print(f"  Unexpected error checking {company}: {e}")
                continue
            for line in log_lines:
                print(line)

            this_run_failed = is_outage(result) or result["elapsed"] > threshold
            previous_breached, consecutive_fails = get_previous_alert_state(state, company)
            previous_entry = state.get(company, {})
            down_since = previous_entry.get("down_since") if isinstance(previous_entry, dict) else None
            previous_is_outage = previous_entry.get("is_outage", False) if isinstance(previous_entry, dict) else False
            total_checks = previous_entry.get("total_checks", 0) + 1 if isinstance(previous_entry, dict) else 1
            response_time_sum = (
                previous_entry.get("response_time_sum", 0.0) if isinstance(previous_entry, dict) else 0.0
            ) + result["elapsed"]
            outage_count = previous_entry.get("outage_count", 0) if isinstance(previous_entry, dict) else 0
            status = "OK" if not this_run_failed else "ALERT"
            print(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {company}: "
                f"{result['elapsed']:.2f}s status={result['status_code']} "
                f"error={result['error']} -> {status}"
            )

            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if not this_run_failed:
                log_result(
                    {
                        "timestamp": timestamp_str,
                        "url": url,
                        "http_status": result["status_code"] or "",
                        "response_time_s": f"{result['elapsed']:.3f}",
                        "slow": "FALSE",
                        "claude_status": "",
                        "claude_analysis": "",
                    }
                )
                state[company] = {
                    "breached": False,
                    "consecutive_fails": 0,
                    "total_checks": total_checks,
                    "response_time_sum": response_time_sum,
                    "outage_count": outage_count,
                }
                save_state(state)
                if previous_breached:
                    generate_status_page(companies, state)
                    deploy_status_page()
                continue

            consecutive_fails += 1
            confirmed = consecutive_fails >= consecutive_failures_required

            claude_status = ""
            reason = fallback_reason(result, threshold)

            log_result(
                {
                    "timestamp": timestamp_str,
                    "url": url,
                    "http_status": result["status_code"],
                    "response_time_s": f"{result['elapsed']:.3f}",
                    "slow": "TRUE",
                    "claude_status": claude_status,
                    "claude_analysis": reason,
                }
            )

            is_down = is_outage(result)

            if not confirmed:
                state[company] = {
                    "breached": False,
                    "consecutive_fails": consecutive_fails,
                    "total_checks": total_checks,
                    "response_time_sum": response_time_sum,
                    "outage_count": outage_count,
                }
                save_state(state)
                continue

            if is_down:
                if not previous_is_outage or not down_since:
                    down_since = timestamp_str
                    outage_count += 1
            else:
                down_since = None

            state[company] = {
                "breached": True,
                "consecutive_fails": consecutive_fails,
                "is_outage": is_down,
                "down_since": down_since,
                "reason": reason,
                "total_checks": total_checks,
                "response_time_sum": response_time_sum,
                "outage_count": outage_count,
            }
            save_state(state)

            if not previous_breached:
                if is_down or alert_on_slow:
                    send_slack_alert(
                        webhook_url,
                        company,
                        url,
                        reason,
                        is_down,
                        result["elapsed"],
                        threshold,
                    )
                generate_status_page(companies, state)
                deploy_status_page()

    save_state(state)
    generate_status_page(companies, state)
    deploy_status_page()


def acquire_lock():
    lock_file = open(LOCK_PATH, "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("Another instance of monitor.py is already running, skipping this run.")
        return None
    lock_file.write(str(os.getpid()))
    lock_file.flush()
    return lock_file


if __name__ == "__main__":
    lock = acquire_lock()
    if lock is None:
        sys.exit(0)
    try:
        sys.exit(main())
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
