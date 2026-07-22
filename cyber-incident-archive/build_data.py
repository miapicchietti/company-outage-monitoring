import csv
import json
import re

FIELDS = [
    "_blank", "event_name", "year", "reported_date", "infiltration_date", "description",
    "event_type", "priority_event_type", "duration", "country_scope", "primary_country",
    "naics", "uk_sic", "sector", "section", "impacted_entities", "number_impacted",
    "threat_actors", "nation_state", "immediate_op_impact", "business_interruption",
    "remediation", "fines_legal", "ransom", "total_financial_impact", "financial_impact_code",
    "financial_impact_type", "response_measures", "stock_original", "stock_trough",
    "stock_pct_decrease", "stock_recovery_time", "sources", "additional_sources", "status",
]


def _num(s):
    if not s:
        return None
    s = s.strip()
    if s.upper() in ("NA", "N/A", ""):
        return None
    s = s.replace("£", "").replace("$", "").replace(",", "").replace("%", "").strip()
    try:
        return float(s)
    except ValueError:
        return None


def load_events():
    with open("cyber_events_raw.csv", newline="") as f:
        rows = list(csv.reader(f))

    events = []
    for row in rows[3:]:
        record = dict(zip(FIELDS, row))
        name = (record.get("event_name") or "").strip()
        year_raw = (record.get("year") or "").strip()
        if not name or not year_raw.isdigit():
            continue
        year = int(year_raw)
        if year < 1990 or year > 2030:
            continue

        record["year"] = year
        record["total_financial_impact"] = _num(record["total_financial_impact"])
        # "Immediate Operational Impact" is free text in the source ("IT outages,
        # class cancellations, ..."), never a number -- keep it as prose, don't
        # try to numify it into the cost breakdown.
        record["immediate_op_impact"] = (record.get("immediate_op_impact") or "").strip()
        record["business_interruption"] = _num(record["business_interruption"])
        record["remediation"] = _num(record["remediation"])
        record["fines_legal"] = _num(record["fines_legal"])
        record["ransom"] = _num(record["ransom"])
        record["stock_pct_decrease"] = _num(record["stock_pct_decrease"])
        record["nation_state"] = (record.get("nation_state") or "").strip().lower().startswith("y")

        # Collapse the free-text "Event Type" into one of a small fixed set for
        # consistent categorical coloring -- the raw column has ~30 near-duplicate
        # phrasings ("Suspected ransomware", "Ransomware, data breach", etc.)
        priority = (record.get("priority_event_type") or "").strip()
        record["category"] = priority if priority in (
            "Ransomware", "Data Breach", "DDoS", "Worm/Malware", "Other"
        ) else "Other"

        for key in ("event_name", "description", "sector", "threat_actors", "duration",
                    "primary_country", "country_scope", "response_measures",
                    "impacted_entities", "number_impacted", "sources"):
            record[key] = (record.get(key) or "").strip()

        events.append(record)

    return events


if __name__ == "__main__":
    events = load_events()
    print(f"parsed {len(events)} events")
    years = sorted({e["year"] for e in events})
    print("year range", years[0], "-", years[-1])
    total_impact = sum(e["total_financial_impact"] or 0 for e in events)
    print("total financial impact (£m, as-reported):", round(total_impact, 1))
    with_impact = [e for e in events if e["total_financial_impact"]]
    print("events with a disclosed financial figure:", len(with_impact))
    from collections import Counter
    print(Counter(e["category"] for e in events))
    with open("events.json", "w") as f:
        json.dump(events, f, indent=1)
