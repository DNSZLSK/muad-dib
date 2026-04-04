"""
GitHub Advisory Database checker.

Fetches all npm malware advisories from the GitHub Advisory Database API.
Supports optional GITHUB_TOKEN env var for higher rate limits.
"""

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

import requests

log = logging.getLogger("auto-labeler.ghsa")

GHSA_API = "https://api.github.com/advisories"
INDEX_FILENAME = "ghsa-index.json"
# Cache validity: 12 hours
CACHE_TTL_SECONDS = 12 * 3600


def _get_headers():
    token = os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        log.info("Using GITHUB_TOKEN for GHSA API (5000 req/h)")
    else:
        log.info("No GITHUB_TOKEN — GHSA API limited to 60 req/h")
    return headers


def fetch_malware_advisories():
    """Fetch all npm malware advisories from GHSA. Returns list of advisories."""
    headers = _get_headers()
    advisories = []
    page = 1
    per_page = 100

    while True:
        params = {
            "type": "malware",
            "ecosystem": "npm",
            "per_page": per_page,
            "page": page,
        }

        for attempt in range(3):
            try:
                resp = requests.get(GHSA_API, headers=headers, params=params, timeout=30)

                if resp.status_code == 403:
                    # Rate limited
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    log.warning("GHSA rate limited, waiting %ds", retry_after)
                    time.sleep(retry_after)
                    continue

                resp.raise_for_status()
                break
            except requests.RequestException as e:
                wait = 2 ** attempt * 5
                log.warning("GHSA request failed (attempt %d): %s — retrying in %ds",
                            attempt + 1, e, wait)
                time.sleep(wait)
        else:
            log.error("GHSA fetch failed after 3 attempts on page %d", page)
            break

        batch = resp.json()
        if not batch:
            break

        advisories.extend(batch)
        log.info("GHSA page %d: %d advisories (total: %d)", page, len(batch), len(advisories))

        if len(batch) < per_page:
            break
        page += 1
        time.sleep(1)  # Courtesy delay

    return advisories


def build_index(cache_dir):
    """Build GHSA index from API. Returns dict keyed by package name."""
    advisories = fetch_malware_advisories()
    index = {}

    for adv in advisories:
        ghsa_id = adv.get("ghsa_id", "")
        published = adv.get("published_at", "")
        summary = adv.get("summary", "")
        withdrawn = adv.get("withdrawn_at")

        # Skip withdrawn advisories
        if withdrawn:
            continue

        for vuln in adv.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            ecosystem = pkg.get("ecosystem", "").lower()
            name = pkg.get("name", "")

            if ecosystem != "npm" or not name:
                continue

            version_range = vuln.get("vulnerable_version_range", "")

            entry = {
                "source": "ghsa",
                "ghsa_id": ghsa_id,
                "date": published,
                "summary": summary[:200],
                "version_range": version_range,
            }

            # Index by package name (version matching is approximate for GHSA)
            if name not in index:
                index[name] = []
            index[name].append(entry)

    log.info("GHSA index: %d packages from %d advisories", len(index), len(advisories))

    # Cache to disk
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / INDEX_FILENAME
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump({"built_at": datetime.utcnow().isoformat() + "Z",
                    "count": len(index),
                    "index": index}, f)
    log.info("GHSA index cached to %s", cache_path)

    return index


def load_cached_index(cache_dir):
    """Load index from cache if fresh enough."""
    cache_path = Path(cache_dir) / INDEX_FILENAME
    if not cache_path.is_file():
        return None
    try:
        stat = cache_path.stat()
        age = time.time() - stat.st_mtime
        if age > CACHE_TTL_SECONDS:
            log.info("GHSA cache expired (%.1fh old)", age / 3600)
            return None

        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        log.info("Loaded cached GHSA index (%d packages, built %s)",
                 data.get("count", 0), data.get("built_at", "?"))
        return data.get("index", {})
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Failed to load GHSA cache: %s", e)
        return None


def lookup(index, name):
    """Check if a package name is in the GHSA index.

    Returns the list of advisory entries or None.
    """
    entries = index.get(name)
    return entries if entries else None
