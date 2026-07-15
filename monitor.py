#!/usr/bin/env python3
"""Synthetic monitoring: times each company's homepage and alerts to Slack."""

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
MIN_DEPLOY_INTERVAL_SECONDS = 180
CSV_FIELDS = [
    "timestamp",
    "url",
    "http_status",
    "response_time_s",
    "slow",
    "claude_status",
    "claude_analysis",
]


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
    except requests.exceptions.ConnectionError:
        result_holder["status_code"] = None
        result_holder["error"] = "Connection Error"
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


def _status_row(company, url, state_label, down_since=None):
    company_esc = html.escape(company)
    url_esc = html.escape(url, quote=True)
    label = {"outage": "Down", "slow": "Slow", "ok": "OK"}[state_label]
    duration = format_down_duration(down_since) if state_label != "ok" else ""
    return (
        f"<tr class='{state_label}' data-name='{company_esc.lower()}'>"
        f"<td>{company_esc}</td>"
        f"<td><a href='{url_esc}'>{url_esc}</a></td>"
        f"<td><span class='pill pill-{state_label}'>{label}</span></td>"
        f"<td class='duration'>{duration}</td>"
        f"</tr>\n"
    )


def generate_status_page(companies, state):
    outages = []
    slow = []
    ok = []
    for company, url in companies:
        entry = state.get(company, {})
        if isinstance(entry, dict) and entry.get("breached"):
            down_since = entry.get("down_since")
            if entry.get("is_outage", True):
                outages.append((company, url, down_since))
            else:
                slow.append((company, url, down_since))
        else:
            ok.append((company, url))

    total = len(outages) + len(slow) + len(ok)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if outages:
        outage_html = "".join(_status_row(c, u, "outage", ds) for c, u, ds in outages)
    else:
        outage_html = (
            "<tr><td colspan='4' class='empty'>No outages right now.</td></tr>\n"
        )

    if slow:
        slow_html = "".join(_status_row(c, u, "slow", ds) for c, u, ds in slow)
    else:
        slow_html = (
            "<tr><td colspan='4' class='empty'>Nothing running slow right now.</td></tr>\n"
        )

    all_rows_html = (
        "".join(_status_row(c, u, "outage", ds) for c, u, ds in outages)
        + "".join(_status_row(c, u, "slow", ds) for c, u, ds in slow)
        + "".join(_status_row(c, u, "ok") for c, u in ok)
    )

    page = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Synthetic Monitor Status</title>
<style>
  :root {{
    --surface-1: #fdfaf7;
    --page-plane: #f7f2ee;
    --text-primary: #23302c;
    --text-secondary: #5c6560;
    --text-muted: #8b8b85;
    --gridline: #e5ded7;
    --border: rgba(35,48,44,0.12);
    --brand-accent: #c1603c;
    --status-good: #0ca30c;
    --status-warning: #fab219;
    --status-critical: #d03b3b;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --surface-1: #212b27;
      --page-plane: #1a221f;
      --text-primary: #ffffff;
      --text-secondary: #cdc7c1;
      --text-muted: #9a948e;
      --gridline: #34413c;
      --border: rgba(255,255,255,0.12);
      --brand-accent: #c1603c;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    background: var(--page-plane);
    color: var(--text-primary);
    margin: 0;
    padding: 0 0 4rem;
    border-top: 6px solid var(--brand-accent);
  }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 2.5rem 1.5rem 0; }}
  h1 {{ font-size: 1.1rem; font-weight: 600; margin: 0 0 0.2rem; color: var(--brand-accent); letter-spacing: 0.01em; }}
  .meta {{ color: var(--text-muted); font-size: 0.85rem; margin: 0 0 1.75rem; }}
  .tiles {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 2rem; }}
  .tile {{
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.1rem;
  }}
  .tile .label {{ font-size: 0.78rem; color: var(--text-secondary); margin-bottom: 0.3rem; }}
  .tile .value {{ font-size: 2rem; font-weight: 600; line-height: 1; }}
  .tile.outage .value {{ color: var(--status-critical); }}
  .tile.slow {{ border-left: 3px solid var(--status-warning); }}
  .tile.ok .value {{ color: var(--status-good); }}
  .tile:not(.outage):not(.slow):not(.ok) .value {{ color: var(--brand-accent); }}
  section {{ margin-bottom: 2rem; }}
  h2 {{ font-size: 0.95rem; font-weight: 600; margin: 0 0 0.75rem; }}
  table {{ border-collapse: collapse; width: 100%; background: var(--surface-1); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }}
  th {{ text-align: left; font-size: 0.75rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em; padding: 0.6rem 0.9rem; border-bottom: 1px solid var(--gridline); }}
  td {{ text-align: left; padding: 0.55rem 0.9rem; border-bottom: 1px solid var(--gridline); font-size: 0.9rem; }}
  tr:last-child td {{ border-bottom: none; }}
  td a {{ color: var(--text-secondary); text-decoration: none; }}
  td a:hover {{ color: var(--brand-accent); text-decoration: underline; }}
  td.duration {{ color: var(--text-secondary); font-variant-numeric: tabular-nums; white-space: nowrap; }}
  .empty {{ color: var(--text-muted); text-align: center; padding: 1.5rem; }}
  .pill {{ display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.78rem; font-weight: 600; }}
  .pill::before {{ content: ''; width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
  .pill-outage {{ color: var(--status-critical); }}
  .pill-outage::before {{ background: var(--status-critical); }}
  .pill-slow {{ color: var(--text-primary); }}
  .pill-slow::before {{ background: var(--status-warning); }}
  .pill-ok {{ color: var(--status-good); }}
  .pill-ok::before {{ background: var(--status-good); }}
  input[type="search"] {{
    width: 100%; padding: 0.55rem 0.8rem; margin-bottom: 0.75rem;
    border: 1px solid var(--border); border-radius: 8px;
    background: var(--surface-1); color: var(--text-primary); font-size: 0.9rem;
  }}
  input[type="search"]:focus {{ outline: none; border-color: var(--brand-accent); }}
  details summary {{ cursor: pointer; font-size: 0.95rem; font-weight: 600; padding: 0.4rem 0; }}
  tr.js-hidden {{ display: none; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Synthetic Monitor Status</h1>
  <p class="meta">Generated {generated_at}</p>

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
    <h2>Outages</h2>
    <table>
      <tr><th>Company</th><th>URL</th><th>Status</th><th>Down for</th></tr>
      {outage_html}
    </table>
  </section>

  <section>
    <h2>Slow</h2>
    <table>
      <tr><th>Company</th><th>URL</th><th>Status</th><th>Down for</th></tr>
      {slow_html}
    </table>
  </section>

  <section>
    <details>
      <summary>All {total} monitored companies</summary>
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


def main():
    config = load_config()
    threshold = config["threshold_seconds"]
    http_timeout = config["http_timeout_seconds"]
    webhook_url = os.environ["SLACK_WEBHOOK_URL"]
    consecutive_failures_required = config.get("consecutive_failures_required", 2)
    alert_on_slow = config.get("alert_on_slow", True)
    state = load_state()
    companies = load_companies()

    for company, url in companies:
        result = check_url(url, http_timeout, company)
        if is_outage(result):
            time.sleep(30)
            result = check_url(url, http_timeout, company)
        this_run_failed = is_outage(result) or result["elapsed"] > threshold
        previous_breached, consecutive_fails = get_previous_alert_state(state, company)
        previous_entry = state.get(company, {})
        down_since = previous_entry.get("down_since") if isinstance(previous_entry, dict) else None
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
            state[company] = {"breached": False, "consecutive_fails": 0}
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
            state[company] = {"breached": False, "consecutive_fails": consecutive_fails}
            save_state(state)
            continue

        if not previous_breached or not down_since:
            down_since = timestamp_str

        state[company] = {
            "breached": True,
            "consecutive_fails": consecutive_fails,
            "is_outage": is_down,
            "down_since": down_since,
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
