#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import feedparser
import requests

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
INCIDENTS_PATH = DATA_DIR / "incidents.json"
FEEDS_PATH = DATA_DIR / "feeds.json"
LAST_UPDATE_PATH = DATA_DIR / "last_update.json"
KEV_PATH = DATA_DIR / "kev.json"

MAX_AUTO_ITEMS = 250  # max auto events kept


def iso_date(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_id(*parts: str) -> str:
    h = hashlib.sha256(("|".join([p or "" for p in parts])).encode("utf-8")).hexdigest()
    return h[:16]


def safe_get(entry: dict, key: str, default=None):
    try:
        return entry.get(key, default)
    except Exception:
        return default


def parse_entry_date(entry) -> str:
    # Try published_parsed > updated_parsed > today
    for k in ("published_parsed", "updated_parsed"):
        t = getattr(entry, k, None)
        if t:
            try:
                dt = datetime(*t[:6], tzinfo=timezone.utc)
                return iso_date(dt)
            except Exception:
                pass
    return iso_date(datetime.now(timezone.utc))


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def fetch_rss(feed_url: str):
    # feedparser can fetch itself, but requests gives clearer errors
    r = requests.get(feed_url, timeout=30)
    r.raise_for_status()
    return feedparser.parse(r.text)


def map_type(entry, default_type: str) -> str:
    # Try tags/categories
    tags = getattr(entry, "tags", None)
    if tags:
        # tags usually list dicts with "term"
        terms = [t.get("term", "").strip() for t in tags if isinstance(t, dict)]
        joined = " ".join([t for t in terms if t]).lower()
        # rough mapping if keywords exist
        if "ransom" in joined:
            return "Ransomware"
        if "phish" in joined:
            return "Phishing"
        if "ddos" in joined:
            return "DDoS"
        if "leak" in joined or "breach" in joined:
            return "DataLeak"
        if "supply" in joined:
            return "SupplyChain"
    return default_type or "Other"


def build_auto_incidents(feeds_cfg):
    items = []
    for feed in feeds_cfg:
        feed_url = feed["feed_url"]
        parsed = fetch_rss(feed_url)

        source_name = feed.get("source_name", "Unknown")
        source_type = feed.get("source_type", "Other")
        country = (feed.get("country") or "").upper()
        scope = feed.get("scope")
        default_conf = feed.get("default_confidence", "Med")
        default_type = feed.get("default_type", "Other")

        for entry in parsed.entries:
            title = getattr(entry, "title", None) or "Untitled"
            link = getattr(entry, "link", None) or ""
            date = parse_entry_date(entry)
            typ = map_type(entry, default_type)

            _id = stable_id(feed.get("id", source_name), link, title, date)

            obj = {
                "id": _id,
                "title": title,
                "type": typ,
                "date": date,
                "country": country if country else "BE",
                "source_type": source_type,
                "source_name": source_name,
                "source_url": link if link else None,
                "confidence": default_conf,
                "generated": True
            }
            if scope:
                obj["scope"] = scope

            # Remove nulls
            obj = {k: v for k, v in obj.items() if v is not None}
            items.append(obj)

    # Sort newest first
    items.sort(key=lambda x: x.get("date", ""), reverse=True)

    # Dedup by id
    dedup = {}
    for it in items:
        dedup[it["id"]] = it

    items = list(dedup.values())
    items.sort(key=lambda x: x.get("date", ""), reverse=True)

    return items[:MAX_AUTO_ITEMS]


def merge_incidents(existing, auto_items):
    """
    Keep manual items (generated != True), replace all generated items with auto_items.
    """
    manual = [x for x in existing if not (isinstance(x, dict) and x.get("generated") is True)]
    # Ensure manual ids exist
    for x in manual:
        if "id" not in x:
            x["id"] = stable_id("manual", x.get("title", ""), x.get("date", ""), x.get("country", ""))
    merged = manual + auto_items
    # Optional: stable sort by date descending
    merged.sort(key=lambda x: x.get("date", ""), reverse=True)
    return merged


def fetch_kev_json():
    # CISA KEV JSON (stable official feed URL)
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = requests.get(url, timeout=40)
    r.raise_for_status()
    data = r.json()
    # Keep it as-is, but add a tiny meta wrapper
    return {
        "source_name": "CISA KEV",
        "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "fetched_at": now_utc_iso(),
        "data": data
    }


def main():
    feeds_cfg = load_json(FEEDS_PATH, [])
    if not feeds_cfg:
        raise SystemExit("feeds.json is missing or empty (data/feeds.json).")

    existing = load_json(INCIDENTS_PATH, [])
    if not isinstance(existing, list):
        existing = []

    auto_items = build_auto_incidents(feeds_cfg)
    merged = merge_incidents(existing, auto_items)
    save_json(INCIDENTS_PATH, merged)

    # Write last update marker
    save_json(LAST_UPDATE_PATH, {
        "updated_at": now_utc_iso(),
        "auto_count": len(auto_items),
        "total_count": len(merged)
    })

    # Also fetch KEV into separate file
    try:
        kev = fetch_kev_json()
        save_json(KEV_PATH, kev)
    except Exception as e:
        # Don't fail the whole pipeline if KEV fetch breaks temporarily
        save_json(KEV_PATH, {
            "error": str(e),
            "fetched_at": now_utc_iso(),
            "source_name": "CISA KEV",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        })


if __name__ == "__main__":
    main()
