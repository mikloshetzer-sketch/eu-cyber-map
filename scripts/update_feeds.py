#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import feedparser
import requests


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"

INCIDENTS_PATH = DATA_DIR / "incidents.json"
FEEDS_PATH = DATA_DIR / "feeds.json"
LAST_UPDATE_PATH = DATA_DIR / "last_update.json"
KEV_PATH = DATA_DIR / "kev.json"
RAW_AUTO_INCIDENTS_PATH = DATA_DIR / "raw_auto_incidents.json"

MAX_AUTO_ITEMS = 250  # max auto events kept


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
    for k in ("published_parsed", "updated_parsed"):
        t = getattr(entry, k, None)
        if t:
            try:
                dt = datetime(*t[:6], tzinfo=timezone.utc)
                return iso_date(dt)
            except Exception:
                pass
    return iso_date(datetime.now(timezone.utc))


def get_entry_text(entry) -> str:
    parts: List[str] = []

    title = getattr(entry, "title", None)
    summary = getattr(entry, "summary", None)
    description = getattr(entry, "description", None)

    if title:
        parts.append(str(title))
    if summary:
        parts.append(str(summary))
    if description:
        parts.append(str(description))

    tags = getattr(entry, "tags", None)
    if tags:
        for t in tags:
            if isinstance(t, dict):
                term = t.get("term")
                if term:
                    parts.append(str(term))

    return " ".join(parts).strip()


def map_type(entry, default_type: str) -> str:
    text = get_entry_text(entry).lower()

    if "ransom" in text:
        return "Ransomware"
    if "phish" in text:
        return "Phishing"
    if "ddos" in text:
        return "DDoS"
    if "leak" in text or "breach" in text or "data leak" in text:
        return "DataLeak"
    if "supply chain" in text or "supply-chain" in text:
        return "SupplyChain"
    if "vulnerab" in text or "advisory" in text or "cve-" in text:
        return "Vulnerability"

    return default_type or "Other"


def _http_get(url: str, headers: Dict[str, str], timeout: int = 30) -> requests.Response:
    return requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)


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
            if 200 <= r.status_code < 300:
                return feedparser.parse(r.text)
            if r.status_code in (401, 403, 429) or (500 <= r.status_code <= 599):
                return None
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


def fetch_json(url: str, timeout: int = 45) -> Any:
    headers = dict(DEFAULT_HEADERS)
    headers["Accept"] = "application/json, */*;q=0.5"
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()


def fetch_text(url: str, timeout: int = 45) -> str:
    headers = dict(DEFAULT_HEADERS)
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.text


def normalize_country(feed_country: Optional[str]) -> Optional[str]:
    c = str(feed_country or "").strip().upper()
    if not c:
        return None
    return c


def is_placeholder_text(value: str) -> bool:
    v = (value or "").lower()
    return (
        "példa" in v or
        "example" in v or
        "fallback" in v or
        " teszt" in v or
        "test " in v or
        v.startswith("test") or
        "dummy" in v
    )


def is_placeholder_record(item: Dict[str, Any]) -> bool:
    fields = [
        item.get("title", ""),
        item.get("source_name", ""),
        item.get("source_url", ""),
        item.get("operator", ""),
        item.get("target_name", ""),
        item.get("scope", "")
    ]
    combined = " ".join(str(x) for x in fields if x).lower()

    if "example.com" in combined:
        return True

    return is_placeholder_text(combined)


def is_valid_source_url(url: str) -> bool:
    u = str(url or "").strip().lower()
    if not u:
        return False
    if not (u.startswith("http://") or u.startswith("https://")):
        return False
    if "example.com" in u:
        return False
    return True


def record_quality_issues(item: Dict[str, Any]) -> List[str]:
    issues: List[str] = []

    if is_placeholder_record(item):
        issues.append("placeholder_record")

    if not item.get("title"):
        issues.append("missing_title")

    if not item.get("date"):
        issues.append("missing_date")

    if not item.get("source_name"):
        issues.append("missing_source_name")

    if not is_valid_source_url(item.get("source_url", "")):
        issues.append("invalid_source_url")

    return issues


def clean_auto_items(auto_items: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    cleaned: List[Dict[str, Any]] = []
    logs: List[str] = []
    seen_keys = set()

    for item in auto_items:
        issues = record_quality_issues(item)
        if issues:
            logs.append(
                f"DROP auto item id={item.get('id')} title={item.get('title','<no-title>')} issues={','.join(issues)}"
            )
            continue

        dedup_key = (
            str(item.get("title", "")).strip().lower(),
            str(item.get("date", "")).strip(),
            str(item.get("source_name", "")).strip().lower(),
        )
        if dedup_key in seen_keys:
            logs.append(
                f"DROP duplicate item id={item.get('id')} title={item.get('title','<no-title>')}"
            )
            continue
        seen_keys.add(dedup_key)

        cleaned.append(item)

    cleaned.sort(key=lambda x: x.get("date", ""), reverse=True)
    return cleaned[:MAX_AUTO_ITEMS], logs


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
        country = normalize_country(feed.get("country"))
        scope = feed.get("scope")
        default_conf = feed.get("default_confidence", "Med")
        default_type = feed.get("default_type", "Other")
        record_type = feed.get("record_type", "incident")
        feed_id = feed.get("id", source_name)

        referer = feed.get("referer") or "https://cert.europa.eu/"

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

            if not is_valid_source_url(link):
                logs.append(f"[{feed_id}] SKIP entry without valid link: {title}")
                continue

            _id = stable_id(str(feed_id), link, title, date)

            obj: Dict[str, Any] = {
                "id": _id,
                "title": title,
                "type": typ,
                "record_type": record_type,
                "date": date,
                "source_type": source_type,
                "source_name": source_name,
                "source_url": link,
                "confidence": default_conf,
                "generated": True
            }

            if country:
                obj["country"] = country
            if scope:
                obj["scope"] = scope

            obj = {k: v for k, v in obj.items() if v is not None}
            items.append(obj)

    items.sort(key=lambda x: x.get("date", ""), reverse=True)

    dedup: Dict[str, Dict[str, Any]] = {}
    for it in items:
        dedup[it["id"]] = it

    items = list(dedup.values())
    items.sort(key=lambda x: x.get("date", ""), reverse=True)

    return items[:MAX_AUTO_ITEMS], logs


def extract_ncsc_json_links(index_html: str, base_url: str) -> List[str]:
    matches = re.findall(r'href="([^"]+\.json)"', index_html, flags=re.IGNORECASE)
    urls: List[str] = []
    for href in matches:
        full = urljoin(base_url + "/", href)
        if full not in urls:
            urls.append(full)
    return urls


def pick_ncsc_confidence(doc: Dict[str, Any]) -> str:
    text = json.dumps(doc, ensure_ascii=False).lower()
    if "critical" in text:
        return "High"
    if "high" in text:
        return "Med"
    return "Med"


def parse_ncsc_type(doc: Dict[str, Any]) -> str:
    text = json.dumps(doc, ensure_ascii=False).lower()

    if "ransom" in text:
        return "Ransomware"
    if "phish" in text:
        return "Phishing"
    if "ddos" in text:
        return "DDoS"
    if "leak" in text or "breach" in text:
        return "DataLeak"
    if "supply chain" in text or "supply-chain" in text:
        return "SupplyChain"
    if "vulnerab" in text or "cve-" in text:
        return "Vulnerability"

    return "Vulnerability"


def fetch_ncsc_nl_csaf(max_docs: int = 80) -> Tuple[List[Dict[str, Any]], List[str]]:
    logs: List[str] = []
    items: List[Dict[str, Any]] = []

    current_year = datetime.now(timezone.utc).year
    years = [str(current_year), str(current_year - 1)]

    for year in years:
        index_url = f"https://advisories.ncsc.nl/csaf/v2/{year}"
        logs.append(f"[ncsc-nl-csaf] GET index {index_url}")

        try:
            html = fetch_text(index_url)
        except Exception as e:
            logs.append(f"[ncsc-nl-csaf] ERROR index fetch failed for {year}: {e}")
            continue

        json_links = extract_ncsc_json_links(html, index_url)
        json_links = sorted(json_links, reverse=True)[:max_docs]

        logs.append(f"[ncsc-nl-csaf] found {len(json_links)} json docs in {year}")

        for url in json_links:
            try:
                doc = fetch_json(url)
            except Exception as e:
                logs.append(f"[ncsc-nl-csaf] ERROR doc fetch failed {url}: {e}")
                continue

            tracking = doc.get("tracking", {}) if isinstance(doc, dict) else {}
            document = doc.get("document", {}) if isinstance(doc, dict) else {}

            title = (
                document.get("title")
                or tracking.get("id")
                or url.rsplit("/", 1)[-1]
            )

            date = (
                tracking.get("initial_release_date")
                or tracking.get("current_release_date")
                or iso_date(datetime.now(timezone.utc))
            )
            date = str(date)[:10]

            item = {
                "id": stable_id("ncsc-nl-csaf", url, title, date),
                "title": title,
                "type": parse_ncsc_type(doc),
                "record_type": "advisory",
                "date": date,
                "country": "NL",
                "source_type": "Gov",
                "source_name": "NCSC-NL",
                "source_url": url,
                "confidence": pick_ncsc_confidence(doc),
                "generated": True,
                "scope": "Netherlands"
            }

            issues = record_quality_issues(item)
            if issues:
                logs.append(
                    f"[ncsc-nl-csaf] DROP title={title} issues={','.join(issues)}"
                )
                continue

            items.append(item)

    dedup: Dict[str, Dict[str, Any]] = {}
    for it in items:
        dedup[it["id"]] = it

    out = list(dedup.values())
    out.sort(key=lambda x: x.get("date", ""), reverse=True)
    logs.append(f"[ncsc-nl-csaf] final items={len(out)}")
    return out[:MAX_AUTO_ITEMS], logs


def merge_incidents(existing: List[Dict[str, Any]], auto_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    manual = [x for x in existing if not (isinstance(x, dict) and x.get("generated") is True)]

    normalized_manual: List[Dict[str, Any]] = []
    for x in manual:
        if not isinstance(x, dict):
            continue

        if "id" not in x:
            x["id"] = stable_id("manual", x.get("title", ""), x.get("date", ""), x.get("country", ""))

        if "record_type" not in x:
            manual_type = str(x.get("type", "")).lower()
            if manual_type == "vulnerability":
                x["record_type"] = "advisory"
            else:
                x["record_type"] = "incident"

        normalized_manual.append(x)

    merged = normalized_manual + auto_items
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
        "record_type": "kev",
        "fetched_at": now_utc_iso(),
        "data": data
    }


def summarize_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in items:
        key = str(item.get("record_type", "unknown"))
        out[key] = out.get(key, 0) + 1
    return out


def main():
    feeds_cfg = load_json(FEEDS_PATH, [])
    if not feeds_cfg:
        raise SystemExit("feeds.json is missing or empty (data/feeds.json).")

    existing = load_json(INCIDENTS_PATH, [])
    if not isinstance(existing, list):
        existing = []

    raw_feed_items, logs = build_auto_incidents(feeds_cfg)

    ncsc_items, ncsc_logs = fetch_ncsc_nl_csaf(max_docs=60)
    logs.extend(ncsc_logs)

    raw_auto_items = raw_feed_items + ncsc_items
    raw_auto_items.sort(key=lambda x: x.get("date", ""), reverse=True)

    cleaned_auto_items, clean_logs = clean_auto_items(raw_auto_items)
    logs.extend(clean_logs)

    save_json(RAW_AUTO_INCIDENTS_PATH, raw_auto_items)

    merged = merge_incidents(existing, cleaned_auto_items)
    save_json(INCIDENTS_PATH, merged)

    save_json(LAST_UPDATE_PATH, {
        "updated_at": now_utc_iso(),
        "auto_raw_count": len(raw_auto_items),
        "auto_clean_count": len(cleaned_auto_items),
        "total_count": len(merged),
        "record_type_counts": summarize_counts(merged),
        "logs_tail": logs[-80:]
    })

    try:
        kev = fetch_kev_json()
        save_json(KEV_PATH, kev)
    except Exception as e:
        save_json(KEV_PATH, {
            "error": str(e),
            "fetched_at": now_utc_iso(),
            "source_name": "CISA KEV",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "record_type": "kev"
        })

    print("---- FEED UPDATE LOGS ----")
    for line in logs:
        print(line)
    print("---- DONE ----")
    print(f"auto_raw={len(raw_auto_items)} auto_clean={len(cleaned_auto_items)} total={len(merged)}")


if __name__ == "__main__":
    main()
