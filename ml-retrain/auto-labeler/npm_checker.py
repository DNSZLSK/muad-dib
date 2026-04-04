"""
npm registry status checker.

For each suspect package, checks if the package/version still exists on npm.
Extracts publish timing for temporal correlation (quick takedown = strong signal).
Rate-limited to 50 requests/minute with exponential backoff.
Resumable: saves progress to npm-status-cache.json.
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path

import requests

log = logging.getLogger("auto-labeler.npm")

NPM_REGISTRY = "https://registry.npmjs.org"
RATE_LIMIT = 50  # requests per minute
RATE_WINDOW = 60  # seconds
CACHE_FILENAME = "npm-status-cache.json"
# Don't re-check packages checked within this window
RECHECK_INTERVAL_SECONDS = 24 * 3600  # 24h


def _rate_limiter():
    """Generator-based rate limiter. Call next() before each request."""
    timestamps = []
    while True:
        now = time.time()
        # Purge timestamps older than the window
        timestamps = [t for t in timestamps if now - t < RATE_WINDOW]
        if len(timestamps) >= RATE_LIMIT:
            sleep_time = timestamps[0] + RATE_WINDOW - now + 0.1
            log.debug("Rate limit reached, sleeping %.1fs", sleep_time)
            time.sleep(sleep_time)
            now = time.time()
            timestamps = [t for t in timestamps if now - t < RATE_WINDOW]
        timestamps.append(now)
        yield


def _fetch_package_info(session, name, limiter):
    """Fetch package metadata from npm. Returns (status, info) tuple."""
    next(limiter)

    url = f"{NPM_REGISTRY}/{name}"
    for attempt in range(3):
        try:
            resp = session.get(url, timeout=15)

            if resp.status_code == 404:
                return "npm_removed", {"reason": "package_404"}

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 30))
                log.warning("npm 429 for %s, waiting %ds", name, retry_after)
                time.sleep(retry_after)
                continue

            resp.raise_for_status()
            return "npm_available", resp.json()

        except requests.RequestException as e:
            wait = 2 ** attempt * 3
            log.warning("npm fetch failed for %s (attempt %d): %s",
                        name, attempt + 1, e)
            time.sleep(wait)

    return "npm_error", {"reason": "fetch_failed_after_retries"}


def check_suspects(suspects, cache_dir):
    """Check npm status for each suspect. Returns dict of results.

    Args:
        suspects: list of dicts with 'package', 'version', 'ecosystem' keys
        cache_dir: path to cache directory

    Returns:
        dict keyed by "name@version" with status info
    """
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / CACHE_FILENAME

    # Load existing cache for resumability
    cache = _load_cache(cache_path)

    # Deduplicate suspects by name@version, npm only
    unique = {}
    for s in suspects:
        if s.get("ecosystem") != "npm":
            continue
        key = f"{s['package']}@{s['version']}"
        if key not in unique:
            unique[key] = s

    # Filter out recently checked
    now = time.time()
    to_check = {}
    for key, s in unique.items():
        cached = cache.get(key)
        if cached and (now - cached.get("checked_at", 0)) < RECHECK_INTERVAL_SECONDS:
            continue
        to_check[key] = s

    log.info("npm check: %d unique suspects, %d already cached, %d to check",
             len(unique), len(unique) - len(to_check), len(to_check))

    if not to_check:
        return cache

    session = requests.Session()
    session.headers.update({"Accept": "application/json"})
    limiter = _rate_limiter()

    checked = 0
    # Group by package name to avoid redundant fetches
    by_name = {}
    for key, s in to_check.items():
        name = s["package"]
        if name not in by_name:
            by_name[name] = []
        by_name[name].append((key, s))

    total_packages = len(by_name)

    for i, (name, entries) in enumerate(by_name.items()):
        status, info = _fetch_package_info(session, name, limiter)

        if i > 0 and i % 100 == 0:
            log.info("npm check progress: %d/%d packages (%.0f%%)",
                     i, total_packages, i / total_packages * 100)
            _save_cache(cache, cache_path)

        for key, s in entries:
            version = s["version"]
            result = {
                "status": status,
                "checked_at": now,
            }

            if status == "npm_available" and isinstance(info, dict):
                versions = info.get("versions", {})
                time_info = info.get("time", {})

                if version not in versions:
                    result["status"] = "npm_removed"
                    result["reason"] = "version_removed"
                else:
                    result["reason"] = "available"

                # Extract timing for temporal correlation
                publish_time = time_info.get(version)
                if publish_time:
                    result["publish_date"] = publish_time

                # Extract latest version publish time
                modified = time_info.get("modified")
                if modified:
                    result["last_modified"] = modified

            elif status == "npm_removed":
                result["reason"] = "package_404"

            cache[key] = result
            checked += 1

    _save_cache(cache, cache_path)
    log.info("npm check complete: %d packages checked, %d total cached",
             checked, len(cache))

    return cache


def _load_cache(cache_path):
    """Load npm status cache from disk."""
    if not cache_path.is_file():
        return {}
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and "results" in data:
            return data["results"]
        return {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache, cache_path):
    """Save npm status cache to disk."""
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump({
                "saved_at": datetime.utcnow().isoformat() + "Z",
                "count": len(cache),
                "results": cache,
            }, f)
    except OSError as e:
        log.error("Failed to save npm cache: %s", e)


def is_quick_takedown(result, detection_date_str, threshold_hours=72):
    """Check if a package was removed quickly after publish (npm security takedown pattern).

    Returns True if the package was removed AND was published recently
    relative to the detection date (within threshold_hours).
    """
    if result.get("status") != "npm_removed":
        return False

    publish_date = result.get("publish_date")
    if not publish_date:
        return False

    try:
        publish_dt = datetime.fromisoformat(publish_date.replace("Z", "+00:00"))
        detection_dt = datetime.fromisoformat(detection_date_str.replace("Z", "+00:00"))
        delta_hours = (detection_dt - publish_dt).total_seconds() / 3600

        # Package was detected within threshold_hours of publish
        # AND has since been removed → strong takedown signal
        return 0 <= delta_hours <= threshold_hours
    except (ValueError, TypeError):
        return False
