"""
OSSF malicious-packages indexer.

Clones (or updates) the ossf/malicious-packages repo with sparse checkout
limited to osv/malicious/npm/, then parses all OSV JSON files into an index.
Skips osv/withdrawn/ (retracted false positives).
"""

import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path

log = logging.getLogger("auto-labeler.ossf")

OSSF_REPO_URL = "https://github.com/ossf/malicious-packages.git"
OSSF_SPARSE_PATH = "osv/malicious/npm"

INDEX_FILENAME = "ossf-index.json"


def _run_git(args, cwd=None):
    """Run a git command, raise on failure."""
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def clone_or_update(repo_dir):
    """Clone with sparse checkout or git pull if already present."""
    repo_dir = Path(repo_dir)

    if (repo_dir / ".git").is_dir():
        log.info("OSSF repo exists at %s — pulling latest", repo_dir)
        _run_git(["pull", "--ff-only"], cwd=repo_dir)
        return

    log.info("Cloning OSSF repo (sparse, depth=1) to %s", repo_dir)
    repo_dir.mkdir(parents=True, exist_ok=True)

    _run_git(["clone", "--depth", "1", "--filter=blob:none",
              "--sparse", OSSF_REPO_URL, str(repo_dir)])
    _run_git(["sparse-checkout", "set", OSSF_SPARSE_PATH], cwd=repo_dir)
    log.info("OSSF clone complete (sparse: %s)", OSSF_SPARSE_PATH)


def _parse_osv_file(filepath):
    """Parse a single OSV JSON file and yield (key, entry) tuples."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Skipping invalid OSV file %s: %s", filepath, e)
        return

    osv_id = data.get("id", "")
    published = data.get("published", "")
    summary = data.get("summary", "")

    # Extract attack type from database_specific if available
    attack_type = None
    db_specific = data.get("database_specific", {})
    origins = db_specific.get("malicious-packages-origins", [])
    if origins:
        attack_type = origins[0].get("reason", None)

    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        ecosystem = pkg.get("ecosystem", "").lower()
        name = pkg.get("name", "")

        if ecosystem != "npm" or not name:
            continue

        # Collect explicit versions
        versions = affected.get("versions", [])

        # Also extract versions from ranges
        for rng in affected.get("ranges", []):
            events = rng.get("events", [])
            for event in events:
                if "introduced" in event and event["introduced"] != "0":
                    versions.append(event["introduced"])

        entry = {
            "source": "ossf",
            "osv_id": osv_id,
            "date": published,
            "summary": summary[:200],
            "attack_type": attack_type,
        }

        if versions:
            for ver in set(versions):
                yield f"{name}@{ver}", entry
        else:
            # No specific versions — all versions affected
            yield f"{name}@*", entry


def build_index(repo_dir, cache_dir):
    """Build OSSF index from the cloned repo. Returns the index dict."""
    repo_dir = Path(repo_dir)
    cache_dir = Path(cache_dir)
    osv_dir = repo_dir / "osv" / "malicious" / "npm"

    if not osv_dir.is_dir():
        log.error("OSSF osv/malicious/npm/ not found at %s", osv_dir)
        return {}

    index = {}
    file_count = 0
    entry_count = 0

    for root, _dirs, files in os.walk(osv_dir):
        # Skip withdrawn reports
        if "withdrawn" in Path(root).parts:
            continue

        for fname in files:
            if not fname.endswith(".json"):
                continue

            filepath = os.path.join(root, fname)
            file_count += 1

            for key, entry in _parse_osv_file(filepath):
                index[key] = entry
                entry_count += 1

    log.info("OSSF index: %d entries from %d files", entry_count, file_count)

    # Cache to disk
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / INDEX_FILENAME
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump({"built_at": datetime.utcnow().isoformat() + "Z",
                    "count": len(index),
                    "index": index}, f)
    log.info("OSSF index cached to %s", cache_path)

    return index


def load_cached_index(cache_dir):
    """Load index from cache if available."""
    cache_path = Path(cache_dir) / INDEX_FILENAME
    if not cache_path.is_file():
        return None
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        log.info("Loaded cached OSSF index (%d entries, built %s)",
                 data.get("count", 0), data.get("built_at", "?"))
        return data.get("index", {})
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Failed to load OSSF cache: %s", e)
        return None


def lookup(index, name, version):
    """Check if a package@version is in the OSSF index.

    Returns the entry dict or None. Checks both exact version and wildcard.
    """
    exact = index.get(f"{name}@{version}")
    if exact:
        return exact
    return index.get(f"{name}@*")
