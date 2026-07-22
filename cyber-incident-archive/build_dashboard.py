import html as htmlmod
import json
import re
from collections import Counter

from build_data import load_events

EVENTS = load_events()
EVENTS_BY_YEAR_DESC = sorted(EVENTS, key=lambda e: (e["year"], e["reported_date"]), reverse=True)

# cmc_category/cmc_population computed below, after CMC Scale helpers are defined.

# Fixed categorical palette, one hue per Event Type, assigned in a fixed order
# (never cycled/reassigned by filter) and deliberately distinct from any
# status-style red/amber/green semantics -- this dataset has no "state", just
# five kinds of incident.
CATEGORY_COLORS = {
    "Ransomware": "#d97a4a",
    "Data Breach": "#6f9bc7",
    "Worm/Malware": "#a67fc9",
    "DDoS": "#4fb3a9",
    "Other": "#8a8f98",
}
CATEGORY_ORDER = ["Ransomware", "Data Breach", "Worm/Malware", "DDoS", "Other"]

# ---------------- The CMC Scale ----------------
# Recreates the Cyber Monitoring Centre's Category 0-5 severity matrix
# (financial impact x affected population). Grid indices: row 0 = smallest
# financial-impact band (bottom of the exhibit) up to row 4 (largest, top);
# col 0 = smallest affected-population band (left) up to col 4 (largest,
# right). None = combination the exhibit leaves blank (financial impact and
# affected population that far apart essentially don't occur).
CMC_FIN_BANDS = [10, 100, 1000, 5000]  # £m upper bounds for rows 0-3; row 4 is ">5000"
CMC_POP_BANDS = [270, 2700, 27000, 136000]  # upper bounds for cols 0-3; col 4 is ">136000"
CMC_SCALE_GRID = [
    [0, 1, 2, None, None],   # row 0: <£10m
    [1, 1, 2, 2, None],      # row 1: £10m-£100m
    [2, 2, 2, 3, 4],         # row 2: £100m-£1bn
    [2, 2, 3, 4, 4],         # row 3: £1bn-£5bn
    [3, 3, 4, 4, 5],         # row 4: >£5bn
]
CMC_CAT_COLORS = {
    0: ("#9c9c96", "#241c15"),
    1: ("#f3e6da", "#3a2f26"),
    2: ("#eccab0", "#3a2f26"),
    3: ("#e2a06e", "#2e2013"),
    4: ("#d97a4a", "#1b120c"),
    5: ("#b8461f", "#f8f0e8"),
}

# Per CMC's actual published definitions: "Affected Population" is the
# number of ORGANISATIONS (public bodies + registered companies) that
# suffered a financial impact -- explicitly not a count of individual
# people/consumers/records/devices. "Financial Impact" excludes fines,
# regulatory costs, and impacts to individuals, and caps any single
# organisation's contribution at £1bn. Our source CSV wasn't built to this
# schema (its "impacted entities" field is usually a people/record count,
# not an org count), so applying the real definition means most incidents
# simply don't have a usable organisation-count figure -- and are left
# unclassified rather than guessed from a mismatched number.
_ORG_KEYWORDS = re.compile(
    r"(organi[sz]ations?|orgs?|businesses?|companies|institutions?|agenc(?:y|ies)|"
    r"trusts?|providers?|vendors?|suppliers?|entit(?:y|ies)|firms?|hospitals?|branches?)"
)
_NUM_RE = re.compile(r"([\d][\d,]*\.?\d*)\s*(million|billion|thousand|k\b|m\b|bn\b)?(%?)", re.I)


def _parse_org_population(raw):
    """Best-effort: pull the largest number followed by an organisation-type
    word ('organizations', 'companies', 'trusts', ...) out of the free-text
    'Number of Impacted entities/systems' field. Deliberately does NOT fall
    back to just the largest number in the string -- under CMC's real
    definition a customer/individual count is the wrong unit entirely, so
    "no organisation-count mentioned" must resolve to None, not a guess."""
    if not raw:
        return None
    low = raw.lower()
    candidates = []
    for m in _NUM_RE.finditer(low):
        num_str, suffix, pct = m.groups()
        if pct == "%":
            continue
        try:
            num = float(num_str.replace(",", ""))
        except ValueError:
            continue
        if suffix:
            suffix = suffix.lower()
            if suffix.startswith("million") or suffix == "m":
                num *= 1_000_000
            elif suffix.startswith("billion") or suffix == "bn":
                num *= 1_000_000_000
            elif suffix.startswith("thousand") or suffix == "k":
                num *= 1_000
        if num < 1:
            continue
        if _ORG_KEYWORDS.search(low[m.end():m.end() + 25]):
            candidates.append(num)
    return max(candidates) if candidates else None


def _cmc_financial_impact_m(entry):
    """CMC's Financial Impact excludes fines/regulatory costs and caps any
    single organisation's contribution at £1bn. Our data isn't broken down
    finely enough to strip out every excluded cost type, but fines/legal IS
    its own column, so subtract that much at least, then apply the cap."""
    total = entry["total_financial_impact"]
    if total is None:
        return None
    fines = entry["fines_legal"] or 0
    return min(max(total - fines, 0), 1000)


def _band_index(value, bounds):
    for i, bound in enumerate(bounds):
        if value < bound:
            return i
    return len(bounds)


def cmc_category(financial_impact_m, population):
    if financial_impact_m is None or population is None:
        return None
    row = _band_index(financial_impact_m, CMC_FIN_BANDS)
    col = _band_index(population, CMC_POP_BANDS)
    cat = CMC_SCALE_GRID[row][col]
    if cat is not None:
        return cat
    # Blank cell in the exhibit (implausible combination) -- fall back to the
    # nearest defined category to the left in the same row.
    for c in range(col - 1, -1, -1):
        if CMC_SCALE_GRID[row][c] is not None:
            return CMC_SCALE_GRID[row][c]
    return None


for _e in EVENTS:
    _e["cmc_population"] = _parse_org_population(_e["number_impacted"])
    _e["cmc_financial_impact"] = _cmc_financial_impact_m(_e)
    _e["cmc_category"] = cmc_category(_e["cmc_financial_impact"], _e["cmc_population"])


def esc(s):
    return htmlmod.escape(str(s)) if s is not None else ""


def money(v, force_sign=False):
    if v is None:
        return "&mdash;"
    if v >= 1000:
        return f"£{v/1000:.2f}bn"
    return f"£{v:.1f}m"


def cmc_badge_html(cat):
    if cat is None:
        return '<span class="cmc-badge cmc-badge-none">&mdash;</span>'
    bg, fg = CMC_CAT_COLORS[cat]
    return f'<span class="cmc-badge" style="background:{bg};color:{fg}">Cat {cat}</span>'


# ---------------- KPIs ----------------
total_events = len(EVENTS)
with_impact = [e for e in EVENTS if e["total_financial_impact"]]
total_impact = sum(e["total_financial_impact"] for e in with_impact)
costliest = max(EVENTS, key=lambda e: e["total_financial_impact"] or 0)
nation_state_count = sum(1 for e in EVENTS if e["nation_state"])
year_min, year_max = min(e["year"] for e in EVENTS), max(e["year"] for e in EVENTS)

category_counts = Counter(e["category"] for e in EVENTS)

# ---------------- Nation-state vs criminal/unattributed ----------------
def _group_stats(events):
    disclosed = [e["total_financial_impact"] for e in events if e["total_financial_impact"]]
    sector_counter = Counter(e["sector"] or "Unclassified" for e in events)
    return {
        "count": len(events),
        "total_impact": sum(disclosed),
        "avg_impact": (sum(disclosed) / len(disclosed)) if disclosed else None,
        "n_disclosed": len(disclosed),
        "top_sector": sector_counter.most_common(1)[0][0] if sector_counter else "&mdash;",
    }


nation_state_events = [e for e in EVENTS if e["nation_state"]]
criminal_events = [e for e in EVENTS if not e["nation_state"]]
ns_stats = _group_stats(nation_state_events)
cr_stats = _group_stats(criminal_events)

# ---------------- Threat actor rollup ----------------
# The source field is free text with no fixed taxonomy ("ALPHV (BlackCat)" vs
# "AlPHV (BlackCat) & Scattered Spider" vs "Sodinokibi/Revil" for the same
# group). Best-effort: split multi-actor entries, normalize the handful of
# clearly-same-group case/alias variants, and drop "not attributed" placeholders
# -- never merge genuinely distinct/vaguer attributions (e.g. "Chinese hackers"
# is left separate from named APT groups since conflating them would overstate
# confidence the source data doesn't have.
_ACTOR_CANONICAL = [
    (re.compile(r"alphv", re.I), "ALPHV (BlackCat)"),
    (re.compile(r"revil|sodinokibi", re.I), "REvil (Sodinokibi)"),
    (re.compile(r"black basta", re.I), "Black Basta"),
    (re.compile(r"lockbit", re.I), "LockBit"),
    (re.compile(r"scattered spider", re.I), "Scattered Spider"),
    (re.compile(r"lazarus", re.I), "Lazarus Group (North Korea)"),
    (re.compile(r"cl0p", re.I), "Cl0p"),
    (re.compile(r"conti", re.I), "Conti"),
    (re.compile(r"darkside", re.I), "DarkSide"),
]


def _split_actors(raw):
    if not raw:
        return []
    raw = raw.strip()
    low = raw.lower()
    if not raw or low == "na" or low.startswith("na -") or low.startswith("na hackers") or low == "unknown" or low == "unknown user":
        return []
    parts = re.split(r"\s*&\s*|\s*;\s*|,\s*", raw)
    cleaned = []
    for p in parts:
        p = p.strip()
        low_p = p.lower()
        if not p or low_p == "na" or low_p.startswith("na ") or low_p in ("unknown", "unknown user"):
            continue
        canonical = p
        for pattern, name in _ACTOR_CANONICAL:
            if pattern.search(p):
                canonical = name
                break
        cleaned.append(canonical)
    return cleaned


actor_counter = Counter()
actor_impact = Counter()
for e in EVENTS:
    for a in set(_split_actors(e["threat_actors"])):
        actor_counter[a] += 1
        actor_impact[a] += e["total_financial_impact"] or 0

top_actors = actor_counter.most_common(10)
unattributed_count = sum(1 for e in EVENTS if not _split_actors(e["threat_actors"]))

# ---------------- Insights tab ----------------
# "Actionable insights" here means evidence-grounded guidance derived from
# real patterns in this incident dataset -- not a live scan of anyone's own
# systems, so the copy is explicit that these are general best practices the
# data supports, not personalized findings.
_RECENT_YEARS = set(range(year_max - 4, year_max + 1))
_recent_events = [e for e in EVENTS if e["year"] in _RECENT_YEARS]
_recent_counts = Counter(e["category"] for e in _recent_events)
_recent_total = len(_recent_events)

_trend_deltas = []
for cat in CATEGORY_ORDER:
    overall_share = category_counts.get(cat, 0) / total_events
    recent_share = (_recent_counts.get(cat, 0) / _recent_total) if _recent_total else 0
    _trend_deltas.append((cat, overall_share, recent_share, recent_share - overall_share))
_rising_cat, _rising_overall, _rising_recent, _rising_delta = max(_trend_deltas, key=lambda t: t[3])

headline_text = (
    f"{_rising_cat} is the fastest-rising risk in this dataset: it made up "
    f"{_rising_overall:.0%} of all {total_events} tracked incidents, but "
    f"{_rising_recent:.0%} of incidents in the last 5 years ({year_max-4}–{year_max}) "
    f"— a {_rising_delta*100:+.0f}-point jump."
)

category_impact = Counter()
for e in EVENTS:
    category_impact[e["category"]] += e["total_financial_impact"] or 0

CATEGORY_PLAYBOOKS = {
    "Ransomware": [
        "Maintain offline/immutable backups and test restores on a schedule — several incidents here (Colonial Pipeline, JBS) paid a ransom partly because clean backups weren't fast enough to restore from.",
        "Enforce MFA on all remote access, VPNs, and privileged accounts.",
        "Segment networks so one compromised host can't reach core systems.",
        "Rehearse an incident response plan before you need it: decide in advance whether you'd ever pay, who has authority to decide, and who gets called first.",
        "Watch third-party remote-access tools closely — Kaseya and MOVEit both show attackers reaching victims through a vendor's software, not the victim's own systems.",
    ],
    "Data Breach": [
        "Audit third-party and supplier access on a schedule — MOVEit, Blue Yonder, and Target all show breaches propagating through a vendor rather than a direct attack.",
        "Enforce least-privilege access and rotate credentials, especially for accounts with database or bulk-export access.",
        "Encrypt sensitive data at rest and in transit, and monitor for unusual bulk data access.",
        "Have a breach notification playbook ready — regulatory clocks (e.g. the ICO's 72-hour rule) start the moment you know, not once you've finished investigating.",
    ],
    "Worm/Malware": [
        "Patch known vulnerabilities promptly — every worm in this dataset (Code Red, SQL Slammer) exploited a flaw that already had a patch available.",
        "Disable or isolate legacy systems that can't be updated.",
        "Keep endpoint protection and email filtering current — self-propagating malware still spreads fastest through unpatched or unmonitored machines.",
    ],
    "DDoS": [
        "Put a CDN or DDoS-scrubbing service in front of anything public-facing.",
        "Pre-negotiate an escalation path with your ISP/hosting provider before an attack, not during one.",
    ],
    "Other": [
        "Insider and physical-access risk needs its own controls, separate from external-attacker defenses — several incidents in this bucket were contractor- or insider-driven.",
        "Track third-party infrastructure dependencies (cloud providers, SaaS vendors) in your own risk register, since their outages become yours.",
    ],
}

NS_PLAYBOOK = [
    "Focus on long-dwell-time detection, not just perimeter defense — nation-state actors more often prioritize persistent access over immediate disruption.",
    "Critical infrastructure and government-adjacent sectors should assume they are targeted, not just at risk.",
    "Threat intel sharing (NCSC, sector ISACs) matters more here, since attribution and tactics shift per state actor.",
]
CRIMINAL_PLAYBOOK = [
    "This bucket is majority financially motivated — ransomware readiness and backup discipline covers most of this exposure.",
    "\"Unattributed\" doesn't mean unsophisticated — several of the costliest incidents here (M&S, MGM, Caesars) were criminal, not nation-state.",
    "Cyber insurance and an incident-response retainer are worth evaluating given this bucket's higher average disclosed cost.",
]

# ---------------- Overview: mosaic (one cell per event, colored by category) ----------------
mosaic_cells = "".join(
    f'<div class="cell" style="background:{CATEGORY_COLORS[e["category"]]}" '
    f'title="{esc(e["event_name"])} ({e["year"]}) &mdash; {esc(e["category"])}"></div>'
    for e in EVENTS_BY_YEAR_DESC
)
mosaic_legend = "".join(
    f'<span><span class="legend-dot" style="background:{CATEGORY_COLORS[cat]}"></span>{cat} {category_counts.get(cat, 0)}</span>'
    for cat in CATEGORY_ORDER
)

# ---------------- Overview: notable incidents (top 8 by financial impact) ----------------
notable = sorted(with_impact, key=lambda e: -e["total_financial_impact"])[:8]
notable_items = "".join(f'''
<li class="pq-item">
  <span class="pq-dot" style="background:{CATEGORY_COLORS[e["category"]]}"></span>
  <div class="pq-body">
    <div class="pq-name">{esc(e["event_name"])}</div>
    <div class="pq-meta">{e["year"]} &middot; {esc(e["sector"] or "Unclassified")}</div>
  </div>
  <span class="pq-value mono">{money(e["total_financial_impact"])}</span>
</li>''' for e in notable)

# ---------------- Overview: incidents-per-year timeline, stacked by category ----------------
years = list(range(year_min, year_max + 1))
year_category_counts = {y: Counter() for y in years}
for e in EVENTS:
    year_category_counts[e["year"]][e["category"]] += 1
year_totals = {y: sum(year_category_counts[y].values()) for y in years}

TW, TH = 1180, 220
AXIS_Y = TH - 28
SEG_GAP = 2
n_years = len(years)
slot_w = TW / n_years
bar_w = slot_w - 3
max_total = max(year_totals.values()) or 1

timeline_svg = ""
for i, y in enumerate(years):
    x = i * slot_w
    cats_present = [(cat, year_category_counts[y].get(cat, 0)) for cat in CATEGORY_ORDER if year_category_counts[y].get(cat, 0) > 0]
    total_c = year_totals[y]
    if total_c == 0:
        continue
    bar_total_h = (total_c / max_total) * (AXIS_Y - 12)
    gaps = SEG_GAP * (len(cats_present) - 1)
    usable_h = max(bar_total_h - gaps, 2)
    y_cursor = AXIS_Y
    for cat, c in cats_present:
        seg_h = usable_h * (c / total_c)
        y_top = y_cursor - seg_h
        tip = f"{y} &middot; {cat}: {c}"
        timeline_svg += f'<rect x="{x:.1f}" y="{y_top:.1f}" width="{bar_w:.1f}" height="{seg_h:.1f}" rx="1.5" fill="{CATEGORY_COLORS[cat]}"><title>{tip}</title></rect>'
        y_cursor = y_top - SEG_GAP

# year-axis ticks every 5 years, always including the first and last year
tick_years = sorted({y for y in years if y % 5 == 0} | {year_min, year_max})
timeline_ticks = "".join(
    f'<text x="{(years.index(ty) * slot_w + bar_w / 2):.1f}" y="{TH - 8}" '
    f'text-anchor="middle" class="axis-label">{ty}</text>'
    for ty in tick_years
)

# ---------------- Overview: recent incidents table ----------------
recent_rows = "".join(f'''
<tr>
  <td class="mono muted">{e["year"]}</td>
  <td>{esc(e["event_name"])}</td>
  <td><span class="cat-chip" style="color:{CATEGORY_COLORS[e["category"]]};background:{CATEGORY_COLORS[e["category"]]}22">{esc(e["category"])}</span></td>
  <td class="muted">{esc(e["sector"] or "Unclassified")}</td>
  <td class="mono num">{money(e["total_financial_impact"])}</td>
</tr>''' for e in EVENTS_BY_YEAR_DESC[:14])

# ---------------- Incidents tab: master list + detail ----------------
incident_rows = "".join(f'''
<li class="alert-row {'is-selected' if i == 0 else ''}" data-idx="{i}" data-search="{esc((e["event_name"] + " " + (e["sector"] or "") + " " + e["category"] + " " + str(e["year"])).lower())}">
  <input type="checkbox" class="compare-check" data-idx="{i}" title="Add to comparison">
  <span class="cat-chip" style="color:{CATEGORY_COLORS[e["category"]]};background:{CATEGORY_COLORS[e["category"]]}22">{esc(e["category"])}</span>
  <div class="alert-row-body">
    <div class="alert-row-name">{esc(e["event_name"])}</div>
    <div class="alert-row-reason">{e["year"]} &middot; {esc(e["sector"] or "Unclassified")}</div>
  </div>
  <div class="alert-row-time mono">{money(e["total_financial_impact"])}</div>
</li>''' for i, e in enumerate(EVENTS_BY_YEAR_DESC))

events_json = json.dumps([{
    "event_name": e["event_name"], "year": e["year"], "reported_date": e["reported_date"],
    "description": e["description"], "category": e["category"], "sector": e["sector"] or "Unclassified",
    "country": e["primary_country"], "duration": e["duration"], "threat_actors": e["threat_actors"] or "Unknown",
    "nation_state": e["nation_state"], "impacted_entities": e["impacted_entities"],
    "immediate_op_impact": e["immediate_op_impact"],
    "response_measures": e["response_measures"], "sources": e["sources"],
    "total_financial_impact": e["total_financial_impact"],
    "breakdown": {
        "Business interruption": e["business_interruption"],
        "Remediation": e["remediation"],
        "Fines / legal": e["fines_legal"],
        "Ransom": e["ransom"],
    },
    "stock_original": e["stock_original"], "stock_trough": e["stock_trough"],
    "stock_pct_decrease": e["stock_pct_decrease"], "stock_recovery_time": e["stock_recovery_time"],
    "cmc_category": e["cmc_category"],
} for e in EVENTS_BY_YEAR_DESC])

# ---------------- Sectors & Actors tab ----------------
sector_counts = Counter(e["sector"] or "Unclassified" for e in EVENTS)
sector_impact = Counter()
for e in EVENTS:
    sector_impact[e["sector"] or "Unclassified"] += e["total_financial_impact"] or 0
top_sectors = sector_counts.most_common(12)
sector_rows = "".join(f'''
<li class="worst-item">
  <span class="dot" style="background:#d97a4a"></span>
  <div class="worst-body">
    <div class="worst-name">{esc(sector)}</div>
    <div class="worst-meta">{money(sector_impact[sector]) if sector_impact[sector] else "No disclosed impact"}</div>
  </div>
  <div class="worst-uptime mono">{count}</div>
</li>''' for sector, count in top_sectors)

sector_grid_cells = "".join(
    f'<div class="cell" style="background:{CATEGORY_COLORS[e["category"]]}" '
    f'title="{esc(e["event_name"])} &mdash; {esc(e["sector"] or "Unclassified")}"></div>'
    for e in EVENTS_BY_YEAR_DESC
)

actor_rows = "".join(f'''
<li class="worst-item">
  <span class="dot" style="background:#a67fc9"></span>
  <div class="worst-body">
    <div class="worst-name">{esc(actor)}</div>
    <div class="worst-meta">{money(actor_impact[actor]) if actor_impact[actor] else "No disclosed impact"}</div>
  </div>
  <div class="worst-uptime mono">{count}</div>
</li>''' for actor, count in top_actors)

# ---------------- Reports tab ----------------
def _dropdown_filter_html(filter_id, label, options):
    checkboxes = "".join(
        f'<label data-label="{esc(opt.lower())}">'
        f'<input type="checkbox" value="{esc(opt.lower())}"> {esc(opt)}'
        f'</label>'
        for opt in options
    )
    return f'''<div class="dropdown-filter" data-filter-id="{filter_id}">
  <button type="button" class="dropdown-trigger">{esc(label)}<span class="dropdown-badge" style="display:none"></span></button>
  <div class="dropdown-panel" data-filter-id="{filter_id}">
    <input type="search" class="dropdown-search" placeholder="Search {esc(label.lower())}&hellip;">
    <div class="dropdown-options">{checkboxes}</div>
  </div>
</div>'''


countries = sorted({e["primary_country"] or "Unknown" for e in EVENTS})
sectors_for_filter = sorted({e["sector"] or "Unclassified" for e in EVENTS})
location_filter_html = _dropdown_filter_html("location", "Location", countries)
industry_filter_html = _dropdown_filter_html("industry", "Industry", sectors_for_filter)

report_rows = "".join(f'''
<tr class="asset-row" data-name="{esc(e["event_name"].lower())}" data-country="{esc((e["primary_country"] or "unknown").lower())}" data-sector="{esc((e["sector"] or "unclassified").lower())}">
  <td class="mono">{e["year"]}</td>
  <td>{esc(e["event_name"])}</td>
  <td><span class="cat-chip" style="color:{CATEGORY_COLORS[e["category"]]};background:{CATEGORY_COLORS[e["category"]]}22">{esc(e["category"])}</span></td>
  <td class="muted">{esc(e["sector"] or "Unclassified")}</td>
  <td class="muted">{esc(e["primary_country"] or "&mdash;")}</td>
  <td>{'Yes' if e["nation_state"] else 'No'}</td>
  <td class="mono num" data-sort="{e["total_financial_impact"] if e["total_financial_impact"] is not None else -1}">{money(e["total_financial_impact"])}</td>
  <td class="num" data-sort="{e["cmc_category"] if e["cmc_category"] is not None else -1}">{cmc_badge_html(e["cmc_category"])}</td>
</tr>''' for e in EVENTS_BY_YEAR_DESC)

# ---------------- Insights tab ----------------
playbook_cards = "".join(f'''
<div class="card playbook-card">
  <div class="playbook-head">
    <span class="legend-dot" style="background:{CATEGORY_COLORS[cat]}"></span>
    <div class="section-title" style="margin:0;">{esc(cat)}</div>
  </div>
  <div class="playbook-stats">{category_counts.get(cat, 0)} incidents &middot; {money(category_impact[cat]) if category_impact[cat] else "no disclosed impact"}</div>
  <ul class="playbook-list">{"".join(f"<li>{esc(item)}</li>" for item in items)}</ul>
</div>''' for cat, items in CATEGORY_PLAYBOOKS.items())

ns_playbook_html = "".join(f"<li>{esc(item)}</li>" for item in NS_PLAYBOOK)
criminal_playbook_html = "".join(f"<li>{esc(item)}</li>" for item in CRIMINAL_PLAYBOOK)

# The CMC Scale reference exhibit -- financial impact (rows, high to low)
# x affected population (columns, low to high), recreating the source chart.
CMC_ROW_LABELS = ["<£10m", "£10m–£100m", "£100m–£1bn", "£1bn–£5bn", ">£5bn"]
CMC_COL_LABELS = ["<270", "270–2.7k", "2.7k–27k", "27k–136k", ">136k"]

# Which tracked incidents actually land in each (row, col) cell, for the
# hover tooltip -- computed from the same banding logic as cmc_category, not
# just grouped by the final category number, so the tooltip reflects the
# exact cell being hovered rather than every incident that happens to share
# its category.
cmc_cell_incidents = {(r, c): [] for r in range(5) for c in range(5)}
for _e in EVENTS:
    if _e["cmc_financial_impact"] is None or _e["cmc_population"] is None:
        continue
    _row = _band_index(_e["cmc_financial_impact"], CMC_FIN_BANDS)
    _col = _band_index(_e["cmc_population"], CMC_POP_BANDS)
    cmc_cell_incidents[(_row, _col)].append(f'{_e["event_name"]} ({_e["year"]})')

cmc_grid_cells = ""
for row in [4, 3, 2, 1, 0]:
    cmc_grid_cells += f'<div class="cmc-row-label">{esc(CMC_ROW_LABELS[row])}</div>'
    for col in range(5):
        cat = CMC_SCALE_GRID[row][col]
        if cat is None:
            cmc_grid_cells += '<div class="cmc-cell cmc-cell-blank"></div>'
        else:
            bg, fg = CMC_CAT_COLORS[cat]
            names = cmc_cell_incidents[(row, col)]
            tip = "&#10;".join(esc(n) for n in names) if names else "No tracked incidents in this range"
            cmc_grid_cells += (
                f'<div class="cmc-cell" style="background:{bg};color:{fg}" '
                f'data-tip="{tip}">Cat {cat}<span class="cmc-cell-count">{len(names) or ""}</span></div>'
            )
cmc_grid_cells += '<div></div>' + "".join(f'<div class="cmc-col-label">{esc(lbl)}</div>' for lbl in CMC_COL_LABELS)

cmc_classified_count = sum(1 for e in EVENTS if e["cmc_category"] is not None)

PAGE = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyber Incident Archive</title>
<style>
:root, :root[data-theme="dark"] {{
  --bg: #1c2826;
  --bg-grad: radial-gradient(1200px 600px at 12% -8%, #283834 0%, transparent 60%), #1c2826;
  --panel: #263531;
  --panel-raised: #2d3d39;
  --border: rgba(242,236,225,0.12);
  --border-strong: rgba(242,236,225,0.22);
  --text: #f2ece1;
  --text-muted: rgba(242,236,225,0.66);
  --text-faint: rgba(242,236,225,0.44);
  --accent: #d97a4a;
  --accent-soft: rgba(217,122,74,0.16);
  --topnav-bg: rgba(24,34,32,0.85);
  --hover-tint: rgba(242,236,225,0.06);
  --hairline: rgba(242,236,225,0.15);
  --font-display: Georgia, "Iowan Old Style", "Source Serif 4", ui-serif, serif;
  --font-body: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
  --font-mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  color-scheme: dark;
}}
:root[data-theme="light"] {{
  --bg: #f5f0e8;
  --bg-grad: radial-gradient(1200px 600px at 12% -8%, #fffdf9 0%, transparent 60%), #f5f0e8;
  --panel: #ffffff;
  --panel-raised: #f2ece2;
  --border: rgba(33,26,20,0.10);
  --border-strong: rgba(33,26,20,0.22);
  --text: #241c15;
  --text-muted: rgba(36,28,21,0.68);
  --text-faint: rgba(36,28,21,0.48);
  --accent: #b85a34;
  --accent-soft: rgba(184,90,52,0.12);
  --topnav-bg: rgba(245,240,232,0.88);
  --hover-tint: rgba(33,26,20,0.05);
  --hairline: rgba(33,26,20,0.14);
  color-scheme: light;
}}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; padding: 0; }}
body {{ background: var(--bg-grad); color: var(--text); font-family: var(--font-body); font-size: 14px; line-height: 1.5; min-height: 100vh; transition: background 0.15s, color 0.15s; }}
.mono {{ font-family: var(--font-mono); font-variant-numeric: tabular-nums; }}
.muted {{ color: var(--text-muted); }}
a {{ color: var(--accent); }}
.topnav {{ display: flex; align-items: center; gap: 20px; padding: 0 24px; height: 60px; border-bottom: 1px solid var(--border); background: var(--topnav-bg); backdrop-filter: blur(8px); position: sticky; top: 0; z-index: 20; }}
.brand {{ display: flex; align-items: center; gap: 10px; margin-right: 8px; }}
.brand-chip {{ background: #f7f3ec; border-radius: 8px; padding: 6px 10px; display: flex; align-items: center; flex: none; }}
.brand-chip img {{ height: 20px; display: block; }}
.brand-word {{ font-family: var(--font-display); font-weight: 700; font-size: 16.5px; }}
.brand-sub {{ font-size: 10.5px; color: var(--text-faint); text-transform: uppercase; letter-spacing: 0.09em; margin-top: -2px; }}
.tabs {{ display: flex; gap: 4px; flex: 1; }}
.tab-btn {{ appearance: none; border: none; background: transparent; color: var(--text-muted); font-family: var(--font-body); font-size: 13.5px; font-weight: 600; padding: 8px 14px; border-radius: 7px; cursor: pointer; transition: background 0.15s, color 0.15s; }}
.tab-btn:hover {{ background: var(--hover-tint); color: var(--text); }}
.tab-btn.is-active {{ background: var(--accent-soft); color: var(--accent); }}
.nav-right {{ display: flex; align-items: center; gap: 14px; font-size: 11.5px; color: var(--text-muted); }}
.theme-toggle-btn {{
  appearance: none; background: transparent; border: 1px solid var(--border-strong); color: var(--text-muted);
  font-size: 11.5px; font-family: var(--font-body); padding: 6px 11px; border-radius: 999px; cursor: pointer;
}}
.theme-toggle-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
.shell {{ max-width: 1360px; margin: 0 auto; padding: 28px 24px 64px; }}
.tab-panel {{ display: none; animation: fadein 0.25s ease; }}
.tab-panel.is-active {{ display: block; }}
@keyframes fadein {{ from {{ opacity: 0; transform: translateY(4px); }} to {{ opacity: 1; transform: translateY(0); }} }}
h1, h2, h3 {{ font-family: var(--font-display); font-weight: 600; margin: 0; text-wrap: balance; }}
.section-title {{ font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-faint); font-weight: 700; margin: 0 0 12px; }}
.kpi-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }}
.kpi-tile {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; position: relative; overflow: hidden; }}
.kpi-tile::before {{ content: ""; position: absolute; inset: 0 0 auto 0; height: 3px; background: var(--accent); }}
.kpi-label {{ font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-faint); font-weight: 700; }}
.kpi-value {{ font-family: var(--font-display); font-size: 30px; font-weight: 700; margin-top: 8px; font-variant-numeric: tabular-nums; }}
.kpi-foot {{ font-size: 12px; color: var(--text-muted); margin-top: 6px; }}
.card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; }}
.tri-row {{ display: grid; grid-template-columns: 1.1fr 1fr 1fr; gap: 14px; margin-bottom: 14px; align-items: stretch; }}
.duo-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 14px; align-items: stretch; }}
.compare-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
.compare-group-title {{ font-family: var(--font-display); font-size: 15px; font-weight: 700; margin-bottom: 10px; }}
.compare-group-stats {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }}
.insight-headline {{ font-family: var(--font-display); font-size: 19px; font-weight: 700; line-height: 1.4; text-wrap: balance; }}
.playbook-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 14px; }}
.playbook-card {{ display: flex; flex-direction: column; }}
.playbook-head {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }}
.playbook-head .legend-dot {{ width: 9px; height: 9px; border-radius: 3px; }}
.playbook-stats {{ font-size: 12px; color: var(--text-muted); margin-bottom: 12px; }}
.playbook-list {{ list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }}
.playbook-list li {{ font-size: 12.5px; color: var(--text); line-height: 1.55; padding-left: 18px; position: relative; }}
.playbook-list li::before {{ content: ""; position: absolute; left: 0; top: 6px; width: 6px; height: 6px; border-radius: 2px; background: var(--accent); }}
.cmc-scale-layout {{ display: flex; align-items: stretch; gap: 8px; }}
.cmc-axis-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-faint); font-weight: 700; }}
.cmc-axis-y {{ writing-mode: vertical-rl; transform: rotate(180deg); flex: none; display: flex; align-items: center; justify-content: center; padding-bottom: 4px; }}
.cmc-axis-x {{ text-align: center; margin-top: 6px; }}
.cmc-scale-grid {{ flex: 1; display: grid; grid-template-columns: 110px repeat(5, 1fr); gap: 4px; max-width: 640px; }}
.cmc-row-label {{ display: flex; align-items: center; font-size: 11px; color: var(--text-faint); white-space: nowrap; }}
.cmc-cell {{
  aspect-ratio: 1.4; display: flex; align-items: center; justify-content: center; gap: 5px;
  font-size: 12px; font-weight: 700; border-radius: 6px; position: relative; cursor: default;
  transition: transform 0.1s, box-shadow 0.1s;
}}
.cmc-cell:hover {{ transform: scale(1.04); box-shadow: 0 4px 14px rgba(0,0,0,0.3); z-index: 5; }}
.cmc-cell-count {{ font-size: 10px; font-weight: 700; opacity: 0.75; }}
.cmc-cell-blank {{ background: transparent; }}
.cmc-cell[data-tip]:hover::after {{
  content: attr(data-tip); position: absolute; bottom: calc(100% + 8px); left: 50%; transform: translateX(-50%);
  background: #0e1513; border: 1px solid var(--border-strong); color: #f2ece1; font-size: 11px; font-weight: 500;
  padding: 8px 10px; border-radius: 8px; white-space: pre-line; text-align: left; line-height: 1.5;
  min-width: 180px; max-width: 260px; box-shadow: 0 8px 22px rgba(0,0,0,0.4); pointer-events: none; z-index: 10;
}}
.cmc-cell[data-tip]:hover::before {{
  content: ""; position: absolute; bottom: calc(100% + 3px); left: 50%; transform: translateX(-50%);
  border: 5px solid transparent; border-top-color: #0e1513; z-index: 10;
}}
.cmc-col-label {{ text-align: center; font-size: 10px; color: var(--text-faint); padding-top: 4px; }}
.mosaic {{ display: flex; flex-wrap: wrap; gap: 3px; max-height: 168px; overflow: hidden; align-content: flex-start; }}
.cell {{ width: 9px; height: 9px; border-radius: 2px; }}
.mosaic-legend {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; font-size: 11.5px; color: var(--text-muted); }}
.mosaic-legend span {{ display: flex; align-items: center; gap: 5px; }}
.legend-dot {{ width: 7px; height: 7px; border-radius: 2px; display: inline-block; }}
.pq-list {{ list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; max-height: 210px; overflow-y: auto; }}
.pq-item {{ display: flex; align-items: center; gap: 9px; padding: 7px 4px; border-bottom: 1px solid var(--border); }}
.pq-item:last-child {{ border-bottom: none; }}
.pq-dot {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; flex: none; }}
.pq-body {{ flex: 1; min-width: 0; }}
.pq-name {{ font-size: 12.5px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.pq-meta {{ font-size: 11px; color: var(--text-faint); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.pq-value {{ font-size: 12px; color: var(--text); flex: none; }}
.timeline-svg {{ width: 100%; height: 220px; display: block; }}
.axis-label {{ font-size: 9.5px; fill: var(--text-faint); font-family: var(--font-mono); }}
.table-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
th {{ text-align: left; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-faint); font-weight: 700; padding: 8px 10px; border-bottom: 1px solid var(--border-strong); position: sticky; top: 0; background: var(--panel); }}
th.sortable {{ cursor: pointer; user-select: none; }}
th.sortable:hover {{ color: var(--text); }}
td {{ padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
.cat-chip {{ font-size: 10px; font-weight: 700; padding: 3px 7px; border-radius: 5px; white-space: nowrap; }}
.cmc-badge {{ font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 5px; white-space: nowrap; display: inline-block; }}
.cmc-badge-none {{ background: transparent; color: var(--text-faint); }}
.table-scroll {{ max-height: 400px; overflow-y: auto; }}
.alerts-grid {{ display: grid; grid-template-columns: 380px 1fr; gap: 16px; align-items: start; }}
.alert-list {{ list-style: none; margin: 0; padding: 0; max-height: 74vh; overflow-y: auto; }}
.alert-row {{ display: flex; align-items: center; gap: 10px; padding: 11px 14px; border-bottom: 1px solid var(--border); cursor: pointer; transition: background 0.12s; }}
.alert-row:hover {{ background: var(--hover-tint); }}
.alert-row.is-selected {{ background: var(--accent-soft); box-shadow: inset 3px 0 0 var(--accent); }}
.alert-row-body {{ flex: 1; min-width: 0; }}
.alert-row-name {{ font-size: 13px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.alert-row-reason {{ font-size: 11.5px; color: var(--text-faint); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.alert-row-time {{ font-size: 11.5px; color: var(--text-muted); flex: none; }}
.compare-check {{ flex: none; width: 15px; height: 15px; accent-color: var(--accent); cursor: pointer; }}
.compare-bar {{ display: flex; align-items: center; gap: 10px; padding: 0 14px 10px; border-bottom: 1px solid var(--border); margin-bottom: 4px; }}
.compare-bar-label {{ font-size: 12px; color: var(--text-muted); flex: 1; }}
.compare-btn {{
  appearance: none; background: var(--accent); border: none; color: #1b120c; font-size: 12.5px; font-weight: 700;
  padding: 7px 12px; border-radius: 7px; cursor: pointer; flex: none;
}}
.compare-btn:disabled {{ background: var(--panel-raised); color: var(--text-faint); cursor: not-allowed; }}
.compare-clear-btn {{
  appearance: none; background: transparent; border: 1px solid var(--border-strong); color: var(--text-muted);
  font-size: 12.5px; padding: 7px 10px; border-radius: 7px; cursor: pointer; flex: none;
}}
.compare-clear-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
.compare-table-wrap {{ overflow-x: auto; }}
.compare-table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
.compare-table th {{ position: sticky; top: 0; background: var(--panel); }}
.compare-table td, .compare-table th {{ padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
.compare-table td.row-label {{ color: var(--text-faint); font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 700; white-space: nowrap; background: var(--panel); position: sticky; left: 0; }}
.compare-table th.compare-col-head {{ font-family: var(--font-display); font-size: 14px; font-weight: 700; min-width: 190px; }}
.compare-table td.compare-desc {{ font-size: 12px; color: var(--text-muted); line-height: 1.5; max-width: 260px; }}
.detail-head {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 14px; }}
.detail-name {{ font-family: var(--font-display); font-size: 22px; font-weight: 700; }}
.detail-meta {{ font-size: 12.5px; color: var(--text-muted); margin-top: 3px; }}
.detail-desc {{ font-size: 13.5px; color: var(--text); line-height: 1.6; margin: 14px 0; }}
.detail-stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 18px 0; }}
.stat-tile {{ background: var(--panel-raised); border: 1px solid var(--border); border-radius: 10px; padding: 13px 14px; }}
.stat-label {{ font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-faint); font-weight: 700; }}
.stat-value {{ font-family: var(--font-mono); font-size: 18px; font-weight: 600; margin-top: 5px; }}
.section-block {{ margin-top: 18px; }}
.breakdown-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
.breakdown-label {{ font-size: 12px; color: var(--text-muted); width: 160px; flex: none; }}
.breakdown-bar-wrap {{ flex: 1; background: var(--hover-tint); border-radius: 3px; height: 8px; overflow: hidden; }}
.breakdown-bar {{ height: 100%; background: var(--accent); border-radius: 3px; }}
.breakdown-value {{ font-size: 12px; font-family: var(--font-mono); width: 60px; text-align: right; flex: none; }}
.body-text {{ font-size: 13px; color: var(--text-muted); line-height: 1.6; }}
.source-link {{ font-size: 12px; word-break: break-all; }}
.empty-state {{ color: var(--text-faint); font-size: 13px; padding: 40px 0; text-align: center; }}
.net-grid {{ display: flex; flex-wrap: wrap; gap: 3px; }}
.net-grid .cell {{ width: 10px; height: 10px; }}
.net-layout {{ display: grid; grid-template-columns: 1fr 300px 300px; gap: 16px; align-items: start; }}
.worst-list {{ list-style: none; margin: 0; padding: 0; max-height: 560px; overflow-y: auto; }}
.worst-item {{ display: flex; align-items: center; gap: 9px; padding: 9px 4px; border-bottom: 1px solid var(--border); }}
.worst-item:last-child {{ border-bottom: none; }}
.dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; flex: none; }}
.worst-body {{ flex: 1; min-width: 0; }}
.worst-name {{ font-size: 12.5px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.worst-meta {{ font-size: 11px; color: var(--text-faint); }}
.worst-uptime {{ font-size: 13px; color: var(--accent); font-weight: 700; }}
.reports-toolbar {{ display: flex; gap: 10px; margin-bottom: 14px; }}
.search-input {{ flex: 1; max-width: 320px; background: var(--panel-raised); border: 1px solid var(--border-strong); border-radius: 8px; padding: 9px 12px; color: var(--text); font-size: 13px; font-family: var(--font-body); }}
.search-input:focus {{ outline: none; border-color: var(--accent); }}
.asset-table-wrap {{ max-height: 620px; overflow-y: auto; }}
.dropdown-filter {{ position: relative; flex: none; }}
.dropdown-trigger {{
  display: flex; align-items: center; gap: 6px; background: var(--panel-raised); border: 1px solid var(--border-strong);
  border-radius: 8px; padding: 9px 12px; color: var(--text); font-size: 13px; font-family: var(--font-body);
  cursor: pointer;
}}
.dropdown-trigger:hover {{ border-color: var(--accent); }}
.dropdown-badge {{
  background: var(--accent); color: #1b120c; font-size: 10.5px; font-weight: 700;
  border-radius: 999px; padding: 1px 6px; line-height: 1.4;
}}
.dropdown-panel {{
  display: none; position: absolute; top: calc(100% + 6px); left: 0; z-index: 30;
  width: 240px; background: var(--panel-raised); border: 1px solid var(--border-strong);
  border-radius: 10px; padding: 10px; box-shadow: 0 12px 28px rgba(0,0,0,0.35);
}}
.dropdown-filter.open .dropdown-panel {{ display: block; }}
.dropdown-search {{
  width: 100%; background: var(--panel); border: 1px solid var(--border-strong); border-radius: 6px;
  padding: 7px 9px; color: var(--text); font-size: 12.5px; font-family: var(--font-body); margin-bottom: 8px;
}}
.dropdown-search:focus {{ outline: none; border-color: var(--accent); }}
.dropdown-options {{ max-height: 220px; overflow-y: auto; display: flex; flex-direction: column; gap: 2px; }}
.dropdown-options label {{
  display: flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--text-muted);
  padding: 5px 6px; border-radius: 5px; cursor: pointer;
}}
.dropdown-options label:hover {{ background: var(--hover-tint); color: var(--text); }}
.clear-filters-btn {{
  appearance: none; background: transparent; border: 1px solid var(--border-strong); color: var(--text-muted);
  font-size: 13px; font-family: var(--font-body); padding: 9px 12px; border-radius: 8px; cursor: pointer; flex: none;
}}
.clear-filters-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
@media (max-width: 980px) {{
  .tri-row {{ grid-template-columns: 1fr; }}
  .duo-row {{ grid-template-columns: 1fr; }}
  .compare-row {{ grid-template-columns: 1fr; }}
  .alerts-grid {{ grid-template-columns: 1fr; }}
  .net-layout {{ grid-template-columns: 1fr; }}
  .kpi-row {{ grid-template-columns: repeat(2, 1fr); }}
}}
</style>
</head>
<body>

<div class="topnav">
  <div class="brand">
    <div class="brand-chip"><img src="cmc-logo.png" alt="CMC"></div>
    <div>
      <div class="brand-word">Cyber Incident Archive</div>
      <div class="brand-sub">Major cyber events, {year_min}&ndash;{year_max}</div>
    </div>
  </div>
  <div class="tabs">
    <button class="tab-btn is-active" data-tab="overview">Overview</button>
    <button class="tab-btn" data-tab="incidents">Incidents</button>
    <button class="tab-btn" data-tab="sectors">Sectors &amp; Actors</button>
    <button class="tab-btn" data-tab="insights">Insights</button>
    <button class="tab-btn" data-tab="reports">Reports</button>
  </div>
  <div class="nav-right">
    <span>{total_events} incidents tracked</span>
    <button type="button" id="themeToggle" class="theme-toggle-btn">Light mode</button>
  </div>
</div>

<div class="shell">

  <section class="tab-panel is-active" id="tab-overview">
    <div class="kpi-row">
      <div class="kpi-tile">
        <div class="kpi-label">Incidents tracked</div>
        <div class="kpi-value">{total_events}</div>
        <div class="kpi-foot">{year_min}&ndash;{year_max}</div>
      </div>
      <div class="kpi-tile">
        <div class="kpi-label">Total financial impact</div>
        <div class="kpi-value">{money(total_impact)}</div>
        <div class="kpi-foot">As reported, {len(with_impact)} of {total_events} disclosed a figure</div>
      </div>
      <div class="kpi-tile">
        <div class="kpi-label">Costliest single event</div>
        <div class="kpi-value">{money(costliest["total_financial_impact"])}</div>
        <div class="kpi-foot">{esc(costliest["event_name"])} ({costliest["year"]})</div>
      </div>
      <div class="kpi-tile">
        <div class="kpi-label">Nation-state attributed</div>
        <div class="kpi-value">{nation_state_count}</div>
        <div class="kpi-foot">of {total_events} incidents ({nation_state_count/total_events*100:.0f}%)</div>
      </div>
    </div>

    <div class="duo-row">
      <div class="card">
        <div class="section-title">All incidents, by type</div>
        <div class="mosaic">{mosaic_cells}</div>
        <div class="mosaic-legend">{mosaic_legend}</div>
      </div>
      <div class="card">
        <div class="section-title">Notable incidents</div>
        <ul class="pq-list">{notable_items}</ul>
      </div>
    </div>

    <div class="card" style="margin-bottom: 14px;">
      <div class="section-title">Incidents per year, by type</div>
      <svg class="timeline-svg" viewBox="0 0 {TW} {TH}" preserveAspectRatio="none">
        <line x1="0" y1="{AXIS_Y}" x2="{TW}" y2="{AXIS_Y}" style="stroke:var(--hairline)" stroke-width="1"/>
        {timeline_svg}
        {timeline_ticks}
      </svg>
      <div class="mosaic-legend" style="margin-top:10px;">{mosaic_legend}</div>
    </div>

    <div class="card">
      <div class="section-title">Most recent incidents</div>
      <div class="table-wrap table-scroll">
        <table>
          <thead><tr><th>Year</th><th>Event</th><th>Type</th><th>Sector</th><th>Financial impact</th></tr></thead>
          <tbody>{recent_rows}</tbody>
        </table>
      </div>
    </div>
  </section>

  <section class="tab-panel" id="tab-incidents">
    <div class="alerts-grid">
      <div class="card" style="padding: 8px 0;">
        <div style="padding: 2px 14px 10px;">
          <input class="search-input" id="incidentSearch" type="text" placeholder="Search incidents&hellip;" style="max-width:none;width:100%;">
        </div>
        <div class="compare-bar">
          <span class="compare-bar-label" id="compareLabel">Select 2&ndash;4 incidents to compare</span>
          <button type="button" class="compare-clear-btn" id="compareClearBtn" style="display:none;">Clear</button>
          <button type="button" class="compare-btn" id="compareBtn" disabled>Compare</button>
        </div>
        <ul class="alert-list" id="incidentList">{incident_rows}</ul>
      </div>
      <div class="card" id="incidentDetail" style="min-height: 480px;"></div>
    </div>
  </section>

  <section class="tab-panel" id="tab-sectors">
    <div class="card" style="margin-bottom: 14px;">
      <div class="section-title">Nation-state vs. criminal / unattributed</div>
      <div class="compare-row">
        <div>
          <div class="compare-group-title">Nation-state attributed</div>
          <div class="compare-group-stats">
            <div class="stat-tile"><div class="stat-label">Incidents</div><div class="stat-value">{ns_stats["count"]}</div></div>
            <div class="stat-tile"><div class="stat-label">Top sector</div><div class="stat-value" style="font-size:14px">{esc(ns_stats["top_sector"])}</div></div>
            <div class="stat-tile"><div class="stat-label">Total impact ({ns_stats["n_disclosed"]} disclosed)</div><div class="stat-value">{money(ns_stats["total_impact"])}</div></div>
            <div class="stat-tile"><div class="stat-label">Avg impact (disclosed)</div><div class="stat-value">{money(ns_stats["avg_impact"])}</div></div>
          </div>
        </div>
        <div>
          <div class="compare-group-title">Criminal / unattributed</div>
          <div class="compare-group-stats">
            <div class="stat-tile"><div class="stat-label">Incidents</div><div class="stat-value">{cr_stats["count"]}</div></div>
            <div class="stat-tile"><div class="stat-label">Top sector</div><div class="stat-value" style="font-size:14px">{esc(cr_stats["top_sector"])}</div></div>
            <div class="stat-tile"><div class="stat-label">Total impact ({cr_stats["n_disclosed"]} disclosed)</div><div class="stat-value">{money(cr_stats["total_impact"])}</div></div>
            <div class="stat-tile"><div class="stat-label">Avg impact (disclosed)</div><div class="stat-value">{money(cr_stats["avg_impact"])}</div></div>
          </div>
        </div>
      </div>
    </div>

    <div class="net-layout">
      <div class="card">
        <div class="section-title">All incidents, by type &middot; {total_events}</div>
        <div class="net-grid">{sector_grid_cells}</div>
        <div class="mosaic-legend" style="margin-top:16px;">{mosaic_legend}</div>
      </div>
      <div class="card">
        <div class="section-title">Incidents by sector</div>
        <ul class="worst-list">{sector_rows}</ul>
      </div>
      <div class="card">
        <div class="section-title">Top threat actors</div>
        <ul class="worst-list">{actor_rows}</ul>
        <div class="kpi-foot" style="margin-top:10px;">{unattributed_count} of {total_events} incidents have no confirmed attribution</div>
      </div>
    </div>
  </section>

  <section class="tab-panel" id="tab-insights">
    <div class="card" style="margin-bottom: 14px;">
      <div class="section-title">Key risk signal</div>
      <div class="insight-headline">{headline_text}</div>
    </div>

    <div class="section-title" style="margin: 4px 0 10px;">Mitigation playbook by incident type</div>
    <div class="playbook-grid">{playbook_cards}</div>

    <div class="card" style="margin-top: 14px;">
      <div class="section-title">Nation-state vs. criminal posture</div>
      <div class="compare-row">
        <div>
          <div class="compare-group-title">Nation-state attributed</div>
          <ul class="playbook-list">{ns_playbook_html}</ul>
        </div>
        <div>
          <div class="compare-group-title">Criminal / unattributed</div>
          <ul class="playbook-list">{criminal_playbook_html}</ul>
        </div>
      </div>
    </div>

    <div class="card" style="margin-top: 14px;">
      <div class="section-title">The CMC Scale</div>
      <div class="cmc-scale-layout">
        <div class="cmc-axis-label cmc-axis-y">Financial impact</div>
        <div class="cmc-scale-grid">{cmc_grid_cells}</div>
      </div>
      <div class="cmc-axis-label cmc-axis-x">Affected population (UK organisations)</div>
      <div class="kpi-foot" style="margin-top:14px;">
        {cmc_classified_count} of {total_events} incidents could be classified against this scale. Hover a cell to see which.
        Per CMC's actual methodology, <strong>Affected Population</strong> is the number of UK organisations financially impacted (not individuals),
        and <strong>Financial Impact</strong> excludes fines/regulatory costs and caps any single organisation's contribution at £1bn.
        Most incidents in this dataset only report an individual/consumer count, not an organisation count, so they're deliberately left unclassified here
        rather than scored against the wrong unit &mdash; this is a strict, conservative reading, not a full implementation of CMC's methodology.
      </div>
    </div>

    <div class="kpi-foot" style="margin-top:14px;">
      These are general best-practice recommendations grounded in patterns across the {total_events} tracked incidents &mdash; not a live assessment of any specific organization's systems.
    </div>
  </section>

  <section class="tab-panel" id="tab-reports">
    <div class="kpi-row">
      <div class="kpi-tile">
        <div class="kpi-label">Incidents tracked</div>
        <div class="kpi-value">{total_events}</div>
      </div>
      <div class="kpi-tile">
        <div class="kpi-label">Total financial impact</div>
        <div class="kpi-value">{money(total_impact)}</div>
      </div>
      <div class="kpi-tile">
        <div class="kpi-label">Ransomware incidents</div>
        <div class="kpi-value">{category_counts.get("Ransomware", 0)}</div>
      </div>
      <div class="kpi-tile">
        <div class="kpi-label">Data breach incidents</div>
        <div class="kpi-value">{category_counts.get("Data Breach", 0)}</div>
      </div>
    </div>
    <div class="card">
      <div class="reports-toolbar">
        <input class="search-input" id="reportSearch" type="text" placeholder="Search incidents&hellip;">
        {location_filter_html}
        {industry_filter_html}
        <button type="button" id="clearFilters" class="clear-filters-btn">Clear filters</button>
      </div>
      <div class="table-wrap asset-table-wrap">
        <table id="reportTable">
          <thead>
            <tr>
              <th class="sortable" data-key="num">Year</th>
              <th class="sortable" data-key="name">Event</th>
              <th>Type</th>
              <th>Sector</th>
              <th>Country</th>
              <th>Nation-state</th>
              <th class="sortable" data-key="num">Financial impact</th>
              <th class="sortable" data-key="num">CMC Cat</th>
            </tr>
          </thead>
          <tbody id="reportBody">{report_rows}</tbody>
        </table>
      </div>
    </div>
  </section>

</div>

<script>
(function() {{
  const root = document.documentElement;
  const themeToggle = document.getElementById('themeToggle');
  function applyTheme(theme) {{
    root.setAttribute('data-theme', theme);
    themeToggle.textContent = theme === 'light' ? 'Dark mode' : 'Light mode';
    try {{ localStorage.setItem('cia-theme', theme); }} catch (e) {{}}
  }}
  let saved = 'dark';
  try {{ saved = localStorage.getItem('cia-theme') || 'dark'; }} catch (e) {{}}
  applyTheme(saved);
  themeToggle.addEventListener('click', () => {{
    applyTheme(root.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
  }});
}})();

const INCIDENTS = {events_json};

document.querySelectorAll('.tab-btn').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('is-active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('is-active'));
    btn.classList.add('is-active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('is-active');
  }});
}});

function fmtMoney(v) {{
  if (v == null) return '&mdash;';
  if (v >= 1000) return '£' + (v/1000).toFixed(2) + 'bn';
  return '£' + v.toFixed(1) + 'm';
}}

function renderIncidentDetail(idx) {{
  const e = INCIDENTS[idx];
  const detail = document.getElementById('incidentDetail');
  if (!e) {{ detail.innerHTML = '<div class="empty-state">No incident selected</div>'; return; }}
  const breakdownEntries = Object.entries(e.breakdown).filter(([k, v]) => v != null && v > 0);
  const maxB = Math.max(...breakdownEntries.map(([k, v]) => v), 1);
  const breakdownHtml = breakdownEntries.length ? breakdownEntries.map(([label, v]) => `
    <div class="breakdown-row">
      <div class="breakdown-label">${{label}}</div>
      <div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:${{Math.max(4, v/maxB*100)}}%"></div></div>
      <div class="breakdown-value mono">${{fmtMoney(v)}}</div>
    </div>`).join('') : '<div class="empty-state">No cost breakdown disclosed</div>';

  let stockHtml = '';
  if (e.stock_original != null && e.stock_trough != null) {{
    stockHtml = `
    <div class="section-block">
      <div class="section-title">Stock price impact</div>
      <div class="detail-stats">
        <div class="stat-tile"><div class="stat-label">Original price</div><div class="stat-value">${{e.stock_original}}</div></div>
        <div class="stat-tile"><div class="stat-label">Trough price</div><div class="stat-value">${{e.stock_trough}}</div></div>
        <div class="stat-tile"><div class="stat-label">Recovery time</div><div class="stat-value" style="font-size:14px">${{e.stock_recovery_time || '&mdash;'}}</div></div>
      </div>
    </div>`;
  }}

  const sourceLink = e.sources && e.sources.startsWith('http')
    ? `<a class="source-link" href="${{e.sources}}" target="_blank" rel="noopener">${{e.sources}}</a>`
    : (e.sources || '');

  detail.innerHTML = `
    <div class="detail-head">
      <div>
        <div class="detail-name">${{e.event_name}}</div>
        <div class="detail-meta">${{e.year}} &middot; ${{e.sector}} &middot; ${{e.country || 'Unknown'}}</div>
      </div>
      <div style="display:flex; gap:6px; flex:none;">
        <span class="cat-chip" style="color:${{CATEGORY_COLORS[e.category]}};background:${{CATEGORY_COLORS[e.category]}}22">${{e.category}}</span>
        ${{cmcBadgeHtml(e.cmc_category)}}
      </div>
    </div>
    <p class="detail-desc">${{e.description}}</p>
    <div class="detail-stats">
      <div class="stat-tile"><div class="stat-label">Duration</div><div class="stat-value" style="font-size:15px">${{e.duration || '&mdash;'}}</div></div>
      <div class="stat-tile"><div class="stat-label">Threat actor(s)</div><div class="stat-value" style="font-size:13px">${{e.threat_actors}}</div></div>
      <div class="stat-tile"><div class="stat-label">Nation-state attributed</div><div class="stat-value">${{e.nation_state ? 'Yes' : 'No'}}</div></div>
    </div>
    <div class="section-block">
      <div class="section-title">Operational impact</div>
      <p class="body-text">${{e.immediate_op_impact || 'Not disclosed'}}</p>
    </div>
    <div class="section-block">
      <div class="section-title">Financial impact breakdown</div>
      ${{breakdownHtml}}
    </div>
    ${{stockHtml}}
    <div class="section-block">
      <div class="section-title">Response &amp; mitigation</div>
      <p class="body-text">${{e.response_measures || 'Not disclosed'}}</p>
    </div>
    <div class="section-block">
      <div class="section-title">Source</div>
      <p class="body-text">${{sourceLink || 'Not disclosed'}}</p>
    </div>
  `;
}}

const CATEGORY_COLORS = {json.dumps(CATEGORY_COLORS)};
const CMC_CAT_COLORS = {json.dumps(CMC_CAT_COLORS)};

function cmcBadgeHtml(cat) {{
  if (cat == null) return '<span class="cmc-badge cmc-badge-none">Not classified</span>';
  const [bg, fg] = CMC_CAT_COLORS[cat];
  return `<span class="cmc-badge" style="background:${{bg}};color:${{fg}}">Cat ${{cat}}</span>`;
}}

document.querySelectorAll('.alert-row').forEach(row => {{
  row.addEventListener('click', (e) => {{
    if (e.target.classList.contains('compare-check')) return;
    document.querySelectorAll('.alert-row').forEach(r => r.classList.remove('is-selected'));
    row.classList.add('is-selected');
    renderIncidentDetail(parseInt(row.dataset.idx, 10));
  }});
}});
if (INCIDENTS.length) renderIncidentDetail(0);

const incidentSearch = document.getElementById('incidentSearch');
incidentSearch.addEventListener('input', () => {{
  const q = incidentSearch.value.trim().toLowerCase();
  document.querySelectorAll('#incidentList .alert-row').forEach(row => {{
    row.style.display = row.dataset.search.includes(q) ? '' : 'none';
  }});
}});

// ---- Compare feature ----
const MAX_COMPARE = 4;
const compareSelection = new Set();
const compareBtn = document.getElementById('compareBtn');
const compareLabel = document.getElementById('compareLabel');
const compareClearBtn = document.getElementById('compareClearBtn');

function updateCompareBar() {{
  const n = compareSelection.size;
  compareLabel.textContent = n === 0 ? 'Select 2–4 incidents to compare' : n + ' selected';
  compareBtn.disabled = n < 2;
  compareBtn.textContent = n >= 2 ? `Compare ${{n}}` : 'Compare';
  compareClearBtn.style.display = n > 0 ? '' : 'none';
}}

document.querySelectorAll('.compare-check').forEach(cb => {{
  cb.addEventListener('click', e => e.stopPropagation());
  cb.addEventListener('change', () => {{
    const idx = parseInt(cb.dataset.idx, 10);
    if (cb.checked) {{
      if (compareSelection.size >= MAX_COMPARE) {{
        cb.checked = false;
        compareLabel.textContent = `You can compare up to ${{MAX_COMPARE}} at a time`;
        return;
      }}
      compareSelection.add(idx);
    }} else {{
      compareSelection.delete(idx);
    }}
    updateCompareBar();
  }});
}});

compareClearBtn.addEventListener('click', () => {{
  compareSelection.clear();
  document.querySelectorAll('.compare-check').forEach(cb => {{ cb.checked = false; }});
  updateCompareBar();
}});

function renderCompareView() {{
  const indices = Array.from(compareSelection);
  const items = indices.map(i => INCIDENTS[i]);
  const detail = document.getElementById('incidentDetail');

  const rows = [
    ['Year', e => e.year],
    ['Type', e => `<span class="cat-chip" style="color:${{CATEGORY_COLORS[e.category]}};background:${{CATEGORY_COLORS[e.category]}}22">${{e.category}}</span>`],
    ['Sector', e => e.sector],
    ['Country', e => e.country || '&mdash;'],
    ['Nation-state', e => e.nation_state ? 'Yes' : 'No'],
    ['Duration', e => e.duration || '&mdash;'],
    ['Threat actor(s)', e => e.threat_actors],
    ['Operational impact', e => `<div class="compare-desc">${{e.immediate_op_impact || 'Not disclosed'}}</div>`],
    ['Total financial impact', e => fmtMoney(e.total_financial_impact)],
    ['Business interruption', e => fmtMoney(e.breakdown['Business interruption'])],
    ['Remediation', e => fmtMoney(e.breakdown['Remediation'])],
    ['Fines / legal', e => fmtMoney(e.breakdown['Fines / legal'])],
    ['Ransom', e => fmtMoney(e.breakdown['Ransom'])],
    ['Description', e => `<div class="compare-desc">${{e.description}}</div>`],
  ];

  const headCells = items.map(e => `<th class="compare-col-head">${{e.event_name}}</th>`).join('');
  const bodyRows = rows.map(([label, fn]) => `
    <tr>
      <td class="row-label">${{label}}</td>
      ${{items.map(e => `<td>${{fn(e)}}</td>`).join('')}}
    </tr>
  `).join('');

  detail.innerHTML = `
    <div class="section-title">Comparing ${{items.length}} incidents</div>
    <div class="compare-table-wrap">
      <table class="compare-table">
        <thead><tr><th></th>${{headCells}}</tr></thead>
        <tbody>${{bodyRows}}</tbody>
      </table>
    </div>
  `;
}}

compareBtn.addEventListener('click', () => {{
  document.querySelectorAll('.alert-row').forEach(r => r.classList.remove('is-selected'));
  renderCompareView();
}});

document.querySelectorAll('.dropdown-trigger').forEach(trigger => {{
  trigger.addEventListener('click', e => {{
    e.stopPropagation();
    const filter = trigger.closest('.dropdown-filter');
    const wasOpen = filter.classList.contains('open');
    document.querySelectorAll('.dropdown-filter.open').forEach(f => f.classList.remove('open'));
    if (!wasOpen) filter.classList.add('open');
  }});
}});
document.addEventListener('click', e => {{
  if (!e.target.closest('.dropdown-filter')) {{
    document.querySelectorAll('.dropdown-filter.open').forEach(f => f.classList.remove('open'));
  }}
}});
document.querySelectorAll('.dropdown-search').forEach(search => {{
  search.addEventListener('input', () => {{
    const q = search.value.trim().toLowerCase();
    search.closest('.dropdown-panel').querySelectorAll('.dropdown-options label').forEach(lbl => {{
      lbl.style.display = q.length === 0 || lbl.dataset.label.indexOf(q) !== -1 ? '' : 'none';
    }});
  }});
}});

function checkedValues(filterId) {{
  return Array.from(document.querySelectorAll('.dropdown-panel[data-filter-id="' + filterId + '"] input:checked')).map(cb => cb.value);
}}
function updateBadge(filterId) {{
  const count = checkedValues(filterId).length;
  const badge = document.querySelector('.dropdown-filter[data-filter-id="' + filterId + '"] .dropdown-badge');
  badge.textContent = count;
  badge.style.display = count > 0 ? '' : 'none';
}}
function applyFilters() {{
  const q = document.getElementById('reportSearch').value.trim().toLowerCase();
  const locations = checkedValues('location');
  const industries = checkedValues('industry');
  document.querySelectorAll('#reportBody .asset-row').forEach(row => {{
    const matchesText = q.length === 0 || row.dataset.name.includes(q);
    const matchesLocation = locations.length === 0 || locations.includes(row.dataset.country);
    const matchesIndustry = industries.length === 0 || industries.includes(row.dataset.sector);
    row.style.display = (matchesText && matchesLocation && matchesIndustry) ? '' : 'none';
  }});
}}
document.getElementById('reportSearch').addEventListener('input', applyFilters);
['location', 'industry'].forEach(filterId => {{
  document.querySelectorAll('.dropdown-panel[data-filter-id="' + filterId + '"] input[type=checkbox]').forEach(cb => {{
    cb.addEventListener('change', () => {{ updateBadge(filterId); applyFilters(); }});
  }});
}});
document.getElementById('clearFilters').addEventListener('click', () => {{
  document.getElementById('reportSearch').value = '';
  document.querySelectorAll('.dropdown-panel input[type=checkbox]:checked').forEach(cb => {{ cb.checked = false; }});
  ['location', 'industry'].forEach(updateBadge);
  document.querySelectorAll('.dropdown-filter.open').forEach(f => f.classList.remove('open'));
  applyFilters();
}});

let sortState = {{}};
document.querySelectorAll('#reportTable th.sortable').forEach(th => {{
  th.addEventListener('click', () => {{
    const cellIdx = Array.from(th.parentNode.children).indexOf(th);
    const key = th.dataset.key;
    const asc = sortState[cellIdx] = !sortState[cellIdx];
    const tbody = document.getElementById('reportBody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((r1, r2) => {{
      const c1 = r1.children[cellIdx], c2 = r2.children[cellIdx];
      let v1, v2;
      if (key === 'num') {{
        v1 = parseFloat(c1.dataset.sort || c1.textContent); v2 = parseFloat(c2.dataset.sort || c2.textContent);
      }} else {{
        v1 = c1.textContent.trim().toLowerCase(); v2 = c2.textContent.trim().toLowerCase();
      }}
      if (v1 < v2) return asc ? -1 : 1;
      if (v1 > v2) return asc ? 1 : -1;
      return 0;
    }});
    rows.forEach(r => tbody.appendChild(r));
  }});
}});
</script>
</body>
</html>
"""

with open("index.html", "w") as f:
    f.write(PAGE)
print("wrote index.html", len(PAGE), "bytes")
