#!/usr/bin/env python3
"""Synthetic monitoring: times each company's homepage, screenshots + analyzes
slow/failed responses with Claude, and alerts to Slack."""

import csv
import glob
import json
import os
import subprocess
import sys
from datetime import datetime

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")
CSV_LOG_PATH = os.path.join(BASE_DIR, "monitor_log.csv")
STATE_PATH = os.path.join(BASE_DIR, "state.json")
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


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


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
            headers={"User-Agent": "Mozilla/5.0 (synthetic-monitor)"},
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


def send_slack_alert(webhook_url, company, reason, is_down, elapsed, threshold):
    status_phrase = "is down" if is_down else "is responding slowly"
    emoji = ":red_circle:" if is_down else ":turtle:"
    text = (
        f"{emoji} {company} {status_phrase}\n"
        f"Response time: {elapsed:.2f}s (threshold: {threshold:.2f}s) | Reason: {reason}"
    )
    try:
        requests.post(webhook_url, json={"text": text}, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"  Failed to send Slack alert: {e}")


def send_recovery_alert(webhook_url, company, elapsed, threshold):
    text = (
        f":white_check_mark: {company} is back up\n"
        f"Response time: {elapsed:.2f}s (threshold: {threshold:.2f}s)"
    )
    try:
        requests.post(webhook_url, json={"text": text}, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"  Failed to send Slack alert: {e}")


def main():
    config = load_config()
    threshold = config["threshold_seconds"]
    http_timeout = config["http_timeout_seconds"]
    webhook_url = os.environ["SLACK_WEBHOOK_URL"]
    model = config.get("claude_model", "haiku")
    claude_bin = find_claude_binary()
    state = load_state()

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    for company, url in config["companies"].items():
        result = check_url(url, http_timeout)
        breached = (
            result["error"] is not None
            or result["status_code"] is None
            or result["status_code"] >= 400
            or result["elapsed"] > threshold
        )
        was_breached = state.get(company, False)
        status = "OK" if not breached else "ALERT"
        print(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {company}: "
            f"{result['elapsed']:.2f}s status={result['status_code']} "
            f"error={result['error']} -> {status}"
        )

        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not breached:
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
            if was_breached:
                send_recovery_alert(webhook_url, company, result["elapsed"], threshold)
            state[company] = False
            continue

        state[company] = True

        reason = None
        claude_status = ""
        if not was_breached:
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

        if not was_breached:
            is_down = (
                result["error"] is not None
                or result["status_code"] is None
                or result["status_code"] >= 400
            )
            send_slack_alert(
                webhook_url,
                company,
                reason,
                is_down,
                result["elapsed"],
                threshold,
            )

    save_state(state)


if __name__ == "__main__":
    sys.exit(main())
