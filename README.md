# company-outage-monitoring

Synthetic uptime monitor for a list of UK companies. Every 5 minutes it checks
each company's homepage, tracks outages/slow responses, alerts to Slack, and
publishes a live public status dashboard.

## What it does, in order

1. **`monitor.py`** runs on a schedule (via macOS `launchd`, every 5 minutes).
   It loops through every company in `companies.csv`, makes one HTTP request
   per company, and classifies the result as healthy, slow, or an outage.
2. On a confirmed outage, it posts to Slack (`SLACK_WEBHOOK_URL`).
3. After processing, it regenerates `status.html` (a static dashboard) and
   deploys it to GitHub Pages by committing + pushing to the `gh-pages`
   branch. The live page: `https://miapicchietti.github.io/company-outage-monitoring/`
4. Results get logged to `monitor_log.csv` (one row per check, every run,
   healthy or not) for historical/statistical analysis.

## Files

| File | What it is |
|---|---|
| `monitor.py` | The whole program. Single file, no separate modules. |
| `companies.csv` | The list being monitored: `company,url,flag,industry,size`. `industry`/`size` come from a UK Companies House-derived spreadsheet (SIC code + statutory filing category), not from monitor.py itself. |
| `config.json` | Tunable settings — see below. |
| `state.json` | *(gitignored, runtime-generated)* Per-company state: is it currently breached, how many consecutive fails, when did it start. |
| `monitor_log.csv` | *(gitignored, runtime-generated)* Append-only log, one row per check. Grows ~1GB/month at current scale — no rotation exists yet. |
| `slow_trickle_log.csv` | *(gitignored, runtime-generated)* Diagnostic-only. Records the *true* completion time of any request that blew past the hard timeout, used to sanity-check whether the timeout value is well-calibrated. Safe to delete anytime — nothing depends on it at runtime. |
| `status.html` | *(gitignored, runtime-generated)* The dashboard, regenerated every run and pushed to `gh-pages`. |
| `.pages-worktree/` | *(gitignored)* A second git worktree of this same repo, checked out to the `gh-pages` branch, used purely so `monitor.py` can commit+push the dashboard without touching the `main` branch's working directory. |
| `com.miapicchietti.syntheticmonitor.plist` | The launchd job definition (gitignored — contains the real Slack webhook URL). `.plist.example` is the tracked, credential-free template. |

## Config (`config.json`)

- `threshold_seconds` — response time above which a check is marked "slow" (not an outage). Currently `3.5`, derived from Q3+3×IQR outlier analysis on real response-time data, not a guess.
- `http_timeout_seconds` — hard cap on how long a single check can take before it's called a "Timeout" (currently `30`). Grounded in real data: see "Why the timeout works the way it does" below.
- `consecutive_failures_required` — how many failing checks in a row confirm an outage (currently `1` — confirms immediately, no cross-run debounce).
- `alert_on_slow` — whether "slow" responses trigger a Slack alert (currently `false` — slow only shows on the dashboard, never pings Slack).

## Non-obvious design decisions (read this before changing things)

- **The IPv4 monkeypatch near the top of `monitor.py`** (`urllib3_cn.allowed_gai_family = lambda: socket.AF_INET`) exists because this network has broken/blackholed IPv6 routing — any IPv6 connection attempt stalls for 10+ seconds before falling back to IPv4. Removing this will reintroduce that stall for any company with an IPv6 DNS record.
- **`check_url()` runs the actual request in a daemon thread and enforces the timeout via `thread.join(timeout=...)`, not via `requests`' own `timeout=` parameter.** This is because `requests`' timeout is a *per-read* timeout, not a total-duration one — a server that trickles bytes slowly can dodge it and hang for minutes to hours. The daemon thread means an abandoned slow request can't block the script from exiting or delay the next company's check.
- **`is_outage()`** counts a check as an outage for: any connection-level error (timeout, DNS failure, refused/reset), no status code at all, any 5xx, or a 404. Everything else (2xx, 3xx, and non-404 4xx like 403/429) is treated as healthy — 403/429 specifically mean "site is up but blocking automated traffic," not down.
- **Connection errors are sub-classified** (`_classify_connection_error()`) into DNS Resolution Failed / Connection Refused / Connection Reset / Connection Aborted / generic Connection Error, separate from SSL Error — both the Slack alert and the dashboard show the specific subtype instead of a generic "Connection Error" string.
- **`browser_verify()` catches false positives from both Timeout and Connection Error.** Real HTTP clients occasionally fail to connect (or dodge the timeout) in ways a real browser's networking stack doesn't reproduce. So a confirmed Timeout or Connection Error (any subtype) triggers one real headless-Chromium load via Playwright before it's treated as a genuine outage — if the page loads there, the result is overwritten as healthy. This never fires on 4xx/5xx or on healthy checks, only on those two error types, so it adds no meaningful cost at ~1,800 companies/5min (Playwright is local browser automation, not an API call — no AI/token cost).
- **The 30-second same-client recheck now only applies to Timeout, not Connection Error or 5xx/404.** It was removed entirely once `browser_verify()` existed (reasoning: a real-browser check is a strictly better second opinion than a same-client retry). But in practice, a Timeout and the Playwright verification that follows it can both miss in the same narrow window (observed directly: Leathams Holdings hit a Timeout, the immediate Playwright check also failed to load, and the site was actually healthy seconds later). So Timeout specifically gets one `sleep 30; recheck` before Playwright even runs, giving momentary blips a chance to clear on a plain retry first. Connection Error skips straight to Playwright (no extra sleep — that path hasn't shown the same double-miss issue). 5xx/404 still get no retry at all, since `browser_verify()` doesn't cover them either way.
- **Screenshot analysis via Claude was removed** (it used to run on every new confirmed outage). It was redundant — for the failure types `is_outage()` catches, the HTTP status/error already fully explains the reason; a screenshot never added new information. If you ever want to catch a "200 but the page is actually broken/parked" case (this happened once, a placeholder page from a lapsed domain, HTTP-level checks structurally can't see it), that's a different, unbuilt feature — periodic content verification on *healthy*-looking companies, not on outages.
- **Why the timeout works the way it does**: `http_timeout_seconds` was tuned by logging the *true* completion time of anything that blew past the cap (`slow_trickle_log.csv`) and separating "eventually succeeded anyway" from "was doomed regardless of how long we waited." ~97% of cap-exceeding requests never succeed no matter how long you wait — raising the timeout mostly just makes dead connections take longer to report as dead. The real ceiling came from the rare genuine successes (~26s observed), not from the doomed majority.
- **"Slow" can get stuck**: a company enters "slow" after one check over `threshold_seconds`, but currently needs a single check *under* that threshold to clear — since the threshold is a strict outlier cutoff, a consistently-moderately-slow (but not broken) site may rarely achieve that, and can appear stuck. Not yet fixed; the fix would be requiring a couple of consecutive fast checks to clear, mirroring how confirmation already works.

## Setup for a new machine

1. `python3 -m venv venv && source venv/bin/activate && pip install requests truststore`
2. Copy `com.miapicchietti.syntheticmonitor.plist.example` → real plist, fill in `SLACK_WEBHOOK_URL`, update the hardcoded paths.
3. `cp` it to `~/Library/LaunchAgents/`, then `launchctl load` it.
4. The `gh-pages` branch and worktree need to exist for dashboard deploys to work — see git history around the GitHub Pages migration for how `.pages-worktree` was set up (`git worktree add -b gh-pages .pages-worktree`, then GitHub repo Settings → Pages → deploy from `gh-pages` branch, root).

## Data source

`companies.csv`'s `industry` and `size` columns were populated from a UK
Companies House-derived spreadsheet (`Companies_2000_to_monitor.xlsx`, SIC
codes + statutory filing category for size band: Micro/Small/Medium/Large by
turnover). That spreadsheet isn't part of this repo.
