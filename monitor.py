#!/usr/bin/env python3
"""Synthetic monitoring: times each company's homepage, screenshots + analyzes
slow/failed responses with Claude, and alerts to Slack."""

import csv
import fcntl
import glob
import html
import io
import json
import os
import subprocess
import sys
import zipfile
from datetime import datetime

import truststore

truststore.inject_into_ssl()

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
COMPANIES_CSV_PATH = os.path.join(BASE_DIR, "companies.csv")
SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")
CSV_LOG_PATH = os.path.join(BASE_DIR, "monitor_log.csv")
STATE_PATH = os.path.join(BASE_DIR, "state.json")
LOCK_PATH = os.path.join(BASE_DIR, "monitor.lock")
STATUS_PAGE_PATH = os.path.join(BASE_DIR, "status.html")
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


def find_claude_binary():
    which = subprocess.run(["which", "claude"], capture_output=True, text=True)
    if which.returncode == 0 and which.stdout.strip():
        return which.stdout.strip()
    matches = sorted(
        glob.glob(
            os.path.expanduser(
                "~/.vscode/extensions/anthropic.claude-code-*/resources/native-binary/claude"
            )
        )
    )
    if matches:
        return matches[-1]
    return None


def check_url(url, timeout):
    start = datetime.now()
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
        elapsed = (datetime.now() - start).total_seconds()
        return {
            "elapsed": elapsed,
            "status_code": resp.status_code,
            "error": None,
        }
    except requests.exceptions.Timeout:
        elapsed = (datetime.now() - start).total_seconds()
        return {"elapsed": elapsed, "status_code": None, "error": "Timeout"}
    except requests.exceptions.ConnectionError:
        elapsed = (datetime.now() - start).total_seconds()
        return {"elapsed": elapsed, "status_code": None, "error": "Connection Error"}
    except requests.exceptions.RequestException as e:
        elapsed = (datetime.now() - start).total_seconds()
        return {"elapsed": elapsed, "status_code": None, "error": type(e).__name__}


def take_screenshot(url, company, timestamp):
    from playwright.sync_api import sync_playwright

    safe_name = company.replace(" ", "_")
    path = os.path.join(SCREENSHOT_DIR, f"{safe_name}_{timestamp}.png")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=20000)
            page.screenshot(path=path)
            browser.close()
        return path
    except Exception:
        return None


def analyze_screenshot(claude_bin, screenshot_path, company, url, check_result, model):
    prompt = (
        f"Read the image at {screenshot_path}. This is a screenshot of {company}'s "
        f"website ({url}), which was slow or failed a monitoring check "
        f"(HTTP status: {check_result['status_code']}, response time: "
        f"{check_result['elapsed']:.2f}s, error: {check_result['error']}). "
        "In 6 words or fewer, state the most likely reason (e.g. 'Timeout', "
        "'502 Bad Gateway error page', 'Blank page - failed to load', "
        "'Slow load - large page assets'). Respond with ONLY the short phrase."
    )
    try:
        result = subprocess.run(
            [
                claude_bin,
                "-p",
                prompt,
                "--allowedTools",
                "Read",
                "--model",
                model,
                "--output-format",
                "text",
                "--add-dir",
                BASE_DIR,
                "--no-session-persistence",
            ],
            capture_output=True,
            text=True,
            timeout=45,
        )
        reason = result.stdout.strip()
        return reason if reason else None
    except Exception:
        return None


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


def status_page_link():
    public_url = os.environ.get("NETLIFY_SITE_URL")
    if public_url:
        return public_url
    return f"file://{STATUS_PAGE_PATH}"


def send_slack_alert(webhook_url, company, url, reason, is_down, elapsed, threshold):
    status_phrase = "is down" if is_down else "is responding slowly"
    emoji = ":red_circle:" if is_down else ":turtle:"
    text = (
        f"{emoji} {company} {status_phrase}\n"
        f"{url}\n"
        f"Response time: {elapsed:.2f}s (threshold: {threshold:.2f}s) | Reason: {reason}\n"
        f"View current status: {status_page_link()}"
    )
    try:
        requests.post(webhook_url, json={"text": text}, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"  Failed to send Slack alert: {e}")


def _status_row(company, url, is_down):
    company_esc = html.escape(company)
    url_esc = html.escape(url, quote=True)
    label = "Down" if is_down else "OK"
    cls = "down" if is_down else "ok"
    return (
        f"<tr class='{cls}' data-name='{company_esc.lower()}'>"
        f"<td>{company_esc}</td>"
        f"<td><a href='{url_esc}'>{url_esc}</a></td>"
        f"<td><span class='pill pill-{cls}'>{label}</span></td>"
        f"</tr>\n"
    )


def generate_status_page(companies, state):
    down = []
    ok = []
    for company, url in companies:
        entry = state.get(company, {})
        if isinstance(entry, dict) and entry.get("breached"):
            down.append((company, url))
        else:
            ok.append((company, url))

    total = len(down) + len(ok)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if down:
        attention_html = "".join(_status_row(c, u, True) for c, u in down)
    else:
        attention_html = (
            "<tr><td colspan='3' class='empty'>Nothing down right now.</td></tr>\n"
        )

    all_rows_html = "".join(_status_row(c, u, False) for c, u in ok) + "".join(
        _status_row(c, u, True) for c, u in down
    )

    page = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Synthetic Monitor Status</title>
<style>
  :root {{
    --surface-1: #fcfcfb;
    --page-plane: #f9f9f7;
    --text-primary: #0b0b0b;
    --text-secondary: #52514e;
    --text-muted: #898781;
    --gridline: #e1e0d9;
    --border: rgba(11,11,11,0.10);
    --status-good: #0ca30c;
    --status-critical: #d03b3b;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --surface-1: #1a1a19;
      --page-plane: #0d0d0d;
      --text-primary: #ffffff;
      --text-secondary: #c3c2b7;
      --text-muted: #898781;
      --gridline: #2c2c2a;
      --border: rgba(255,255,255,0.10);
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    background: var(--page-plane);
    color: var(--text-primary);
    margin: 0;
    padding: 2.5rem 1.5rem 4rem;
  }}
  .wrap {{ max-width: 880px; margin: 0 auto; }}
  h1 {{ font-size: 1.1rem; font-weight: 600; margin: 0 0 0.2rem; }}
  .meta {{ color: var(--text-muted); font-size: 0.85rem; margin: 0 0 1.75rem; }}
  .tiles {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; margin-bottom: 2rem; }}
  .tile {{
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.1rem;
  }}
  .tile .label {{ font-size: 0.78rem; color: var(--text-secondary); margin-bottom: 0.3rem; }}
  .tile .value {{ font-size: 2rem; font-weight: 600; line-height: 1; }}
  .tile.down .value {{ color: var(--status-critical); }}
  .tile.ok .value {{ color: var(--status-good); }}
  section {{ margin-bottom: 2rem; }}
  h2 {{ font-size: 0.95rem; font-weight: 600; margin: 0 0 0.75rem; }}
  table {{ border-collapse: collapse; width: 100%; background: var(--surface-1); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }}
  th {{ text-align: left; font-size: 0.75rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em; padding: 0.6rem 0.9rem; border-bottom: 1px solid var(--gridline); }}
  td {{ text-align: left; padding: 0.55rem 0.9rem; border-bottom: 1px solid var(--gridline); font-size: 0.9rem; }}
  tr:last-child td {{ border-bottom: none; }}
  td a {{ color: var(--text-secondary); text-decoration: none; }}
  td a:hover {{ text-decoration: underline; }}
  .empty {{ color: var(--text-muted); text-align: center; padding: 1.5rem; }}
  .pill {{ display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.78rem; font-weight: 600; }}
  .pill::before {{ content: ''; width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
  .pill-down {{ color: var(--status-critical); }}
  .pill-down::before {{ background: var(--status-critical); }}
  .pill-ok {{ color: var(--status-good); }}
  .pill-ok::before {{ background: var(--status-good); }}
  input[type="search"] {{
    width: 100%; padding: 0.55rem 0.8rem; margin-bottom: 0.75rem;
    border: 1px solid var(--border); border-radius: 8px;
    background: var(--surface-1); color: var(--text-primary); font-size: 0.9rem;
  }}
  details summary {{ cursor: pointer; font-size: 0.95rem; font-weight: 600; padding: 0.4rem 0; }}
  tr.js-hidden {{ display: none; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Synthetic Monitor Status</h1>
  <p class="meta">Generated {generated_at}</p>

  <div class="tiles">
    <div class="tile down">
      <div class="label">Down</div>
      <div class="value">{len(down)}</div>
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
    <h2>Needs attention</h2>
    <table>
      <tr><th>Company</th><th>URL</th><th>Status</th></tr>
      {attention_html}
    </table>
  </section>

  <section>
    <details>
      <summary>All {total} monitored companies</summary>
      <div style="margin-top: 0.85rem;">
        <input type="search" id="filter" placeholder="Filter by company name&hellip;">
        <table id="all-table">
          <tr><th>Company</th><th>URL</th><th>Status</th></tr>
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
    token = os.environ.get("NETLIFY_AUTH_TOKEN")
    site_id = os.environ.get("NETLIFY_SITE_ID")
    if not token or not site_id:
        return

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(STATUS_PAGE_PATH, arcname="index.html")
        zf.writestr("_headers", "/*\n  Content-Type: text/html; charset=utf-8\n")

    try:
        requests.post(
            f"https://api.netlify.com/api/v1/sites/{site_id}/deploys",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/zip",
            },
            data=buf.getvalue(),
            timeout=30,
        )
    except requests.exceptions.RequestException as e:
        print(f"  Failed to deploy status page: {e}")


def main():
    config = load_config()
    threshold = config["threshold_seconds"]
    http_timeout = config["http_timeout_seconds"]
    webhook_url = os.environ["SLACK_WEBHOOK_URL"]
    model = config.get("claude_model", "haiku")
    consecutive_failures_required = config.get("consecutive_failures_required", 2)
    alert_on_slow = config.get("alert_on_slow", True)
    claude_bin = find_claude_binary()
    state = load_state()
    companies = load_companies()

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    for company, url in companies:
        result = check_url(url, http_timeout)
        this_run_failed = is_outage(result) or result["elapsed"] > threshold
        previous_breached, consecutive_fails = get_previous_alert_state(state, company)
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

        reason = None
        claude_status = ""
        if confirmed and not previous_breached:
            file_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if claude_bin:
                screenshot_path = take_screenshot(url, company, file_timestamp)
                if screenshot_path:
                    reason = analyze_screenshot(
                        claude_bin, screenshot_path, company, url, result, model
                    )
            claude_status = "TRUE" if reason else "FALSE"

        if not reason:
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

        if not confirmed:
            state[company] = {"breached": False, "consecutive_fails": consecutive_fails}
            save_state(state)
            continue

        state[company] = {"breached": True, "consecutive_fails": consecutive_fails}
        save_state(state)

        if not previous_breached:
            is_down = is_outage(result)
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
