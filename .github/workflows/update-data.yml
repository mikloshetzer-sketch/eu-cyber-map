#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import feedparser
import requests


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"

INCIDENTS_PATH = DATA_DIR / "incidents.json"
FEEDS_PATH = DATA_DIR / "feeds.json"
LAST_UPDATE_PATH = DATA_DIR / "last_update.json"
KEV_PATH = DATA_DIR / "kev.json"

MAX_AUTO_ITEMS = 250  # max auto events kept


# A "browser-ish" header set, to reduce bot-blocking
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Safari/537.36"
    ),
    "Accept": "application/rss+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


def iso_date(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_id(*parts: str) -> str:
    h = hashlib.sha256(("|".join([p or "" for p in parts])).encode("utf-8")).hexdigest()
    return h[:16]


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


def map_type(entry, default_type: str) -> str:
    tags = getattr(entry, "tags", None)
    if tags:
        terms = [t.get("term", "").strip() for t in tags if isinstance(t, dict)]
        joined = " ".join([t for t in terms if t]).lower()
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


def _http_get(url: str, headers: Dict[str, str], timeout: int = 30) -> requests.Response:
    r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    return r


def fetch_rss_with_fallback(
    primary_url: str,
    fallback_url: Optional[str] = None,
    referer: Optional[str] = None
) -> Tuple[Optional[feedparser.FeedParserDict], List[str]]:
    """
    Returns (parsed_feed_or_none, logs)
    - Tries primary
    - On common blocks/errors (403/401/429/5xx) tries fallback if provided
    - Never raises; caller decides what to do
    """
    logs: List[str] = []
    headers = dict(DEFAULT_HEADERS)
    if referer:
        headers["Referer"] = referer

    def try_url(u: str) -> Optional[feedparser.FeedParserDict]:
        logs.append(f"GET {u}")
        try:
            r = _http_get(u, headers=headers, timeout=35)
            logs.append(f" -> status {r.status_code}")
            # If OK, parse
            if 200 <= r.status_code < 300:
                return feedparser.parse(r.text)
            # Treat these as "blocked or transient"
            if r.status_code in (401, 403, 429) or (500 <= r.status_code <= 599):
                return None
            # Other non-2xx: still treat as failure
            return None
        except Exception as e:
            logs.append(f" -> exception: {e}")
            return None

    parsed = try_url(primary_url)
    if parsed is not None:
        return parsed, logs

    if fallback_url:
        logs.append("Primary failed; trying fallback...")
        parsed2 = try_url(fallback_url)
        return parsed2, logs

    return None, logs


def build_auto_incidents(feeds_cfg: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    items: List[Dict[str, Any]] = []
    logs: List[str] = []

    for feed in feeds_cfg:
        primary = feed.get("feed_url")
        fallback = feed.get("fallback_feed_url")
        if not primary:
            logs.append("SKIP feed: missing feed_url")
            continue

        source_name = feed.get("source_name", "Unknown")
        source_type = feed.get("source_type", "Other")
        country = (feed.get("country") or "").upper() or "BE"
        scope = feed.get("scope")
        default_conf = feed.get("default_confidence", "Med")
        default_type = feed.get("default_type", "Other")
        feed_id = feed.get("id", source_name)

        # Use site root as referer
        referer = "https://cert.europa.eu/"

        parsed, f_logs = fetch_rss_with_fallback(primary, fallback_url=fallback, referer=referer)
        logs.extend([f"[{feed_id}] {line}" for line in f_logs])

        if parsed is None:
            logs.append(f"[{feed_id}] ERROR: feed not fetched/parsed (skipping)")
            continue

        if getattr(parsed, "bozo", False):
            logs.append(f"[{feed_id}] WARN: bozo feed parse issue: {getattr(parsed, 'bozo_exception', '')}")

        for entry in parsed.entries:
            title = getattr(entry, "title", None) or "Untitled"
            link = getattr(entry, "link", None) or ""
            date = parse_entry_date(entry)
            typ = map_type(entry, default_type)

            _id = stable_id(str(feed_id), link, title, date)

            obj: Dict[str, Any] = {
                "id": _id,
                "title": title,
                "type": typ,
                "date": date,
                "country": country,
                "source_type": source_type,
                "source_name": source_name,
                "source_url": link if link else None,
                "confidence": default_conf,
                "generated": True
            }
            if scope:
                obj["scope"] = scope

            obj = {k: v for k, v in obj.items() if v is not None}
            items.append(obj)

    # Sort newest first
    items.sort(key=lambda x: x.get("date", ""), reverse=True)

    # Dedup by id
    dedup: Dict[str, Dict[str, Any]] = {}
    for it in items:
        dedup[it["id"]] = it

    items = list(dedup.values())
    items.sort(key=lambda x: x.get("date", ""), reverse=True)

    return items[:MAX_AUTO_ITEMS], logs


def merge_incidents(existing: List[Dict[str, Any]], auto_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Keep manual items, replace generated items
    manual = [x for x in existing if not (isinstance(x, dict) and x.get("generated") is True)]
    for x in manual:
        if "id" not in x:
            x["id"] = stable_id("manual", x.get("title", ""), x.get("date", ""), x.get("country", ""))
    merged = manual + auto_items
    merged.sort(key=lambda x: x.get("date", ""), reverse=True)
    return merged


def fetch_kev_json() -> Dict[str, Any]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    headers = dict(DEFAULT_HEADERS)
    headers["Accept"] = "application/json, */*;q=0.5"
    r = requests.get(url, headers=headers, timeout=45)
    r.raise_for_status()
    data = r.json()
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

    auto_items, logs = build_auto_incidents(feeds_cfg)
    merged = merge_incidents(existing, auto_items)
    save_json(INCIDENTS_PATH, merged)

    # Write last update marker (plus logs to help debugging)
    save_json(LAST_UPDATE_PATH, {
        "updated_at": now_utc_iso(),
        "auto_count": len(auto_items),
        "total_count": len(merged),
        "logs_tail": logs[-60:]  # keep only last ~60 lines
    })

    # Also fetch KEV into separate file
    try:
        kev = fetch_kev_json()
        save_json(KEV_PATH, kev)
    except Exception as e:
        save_json(KEV_PATH, {
            "error": str(e),
            "fetched_at": now_utc_iso(),
            "source_name": "CISA KEV",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        })

    # Print logs to action output
    print("---- FEED UPDATE LOGS ----")
    for line in logs:
        print(line)
    print("---- DONE ----")
    print(f"auto_items={len(auto_items)} total={len(merged)}")


if __name__ == "__main__":
    main()
