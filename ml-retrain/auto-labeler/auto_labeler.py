#!/usr/bin/env python3
"""
MUAD'DIB Auto-Labeling Pipeline

Correlates muaddib suspects with external signals (OSSF, GHSA, npm status)
to produce ground truth labels for ML training.

Usage:
    python auto_labeler.py --full              # Run all steps
    python auto_labeler.py --step ossf         # Run individual step
    python auto_labeler.py --step npm
    python auto_labeler.py --step ghsa
    python auto_labeler.py --step label
    python auto_labeler.py --update            # Cron mode: re-check pending/unconfirmed

Environment:
    GITHUB_TOKEN    Optional, for higher GHSA API rate limits
    MUADDIB_DATA    Override data directory (default: /opt/muaddib/data)
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import ossf_index
import ghsa_checker
import npm_checker
import labeler

# ── Paths ──
MUADDIB_DATA = Path(os.environ.get("MUADDIB_DATA", "/opt/muaddib/data"))
MUADDIB_ALERTS = Path(os.environ.get("MUADDIB_ALERTS", "/opt/muaddib/logs/alerts"))
BASE_DIR = Path(__file__).parent
CACHE_DIR = BASE_DIR / "data"
OSSF_REPO_DIR = CACHE_DIR / "ossf-malicious-packages"
OUTPUT_PATH = MUADDIB_DATA / "auto-labels.json"

log = logging.getLogger("auto-labeler")


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(name)s] %(levelname)s %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%Y-%m-%d %H:%M:%S")


def load_detections():
    """Load detections.json from muaddib data directory."""
    path = MUADDIB_DATA / "detections.json"
    if not path.is_file():
        log.error("detections.json not found at %s", path)
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    detections = data.get("detections", [])
    npm_count = sum(1 for d in detections if d.get("ecosystem") == "npm")
    log.info("Loaded %d detections (%d npm)", len(detections), npm_count)
    return detections


def load_alert_scores():
    """Load risk scores and tiers from individual alert files.

    Scans logs/alerts/ for JSON files and extracts score + tier info.
    Returns dict keyed by "name@version".
    """
    scores = {}

    # Try cached scores first
    cache_path = CACHE_DIR / "alert-scores-cache.json"
    if cache_path.is_file():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if cached.get("count", 0) > 0:
                log.info("Loaded %d cached alert scores", cached["count"])
                return cached.get("scores", {})
        except (json.JSONDecodeError, OSError):
            pass

    if not MUADDIB_ALERTS.is_dir():
        log.warning("Alerts directory not found at %s — scores will be estimated from severity",
                     MUADDIB_ALERTS)
        return scores

    alert_files = list(MUADDIB_ALERTS.glob("*.json"))
    log.info("Scanning %d alert files for scores...", len(alert_files))

    for filepath in alert_files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                alert = json.load(f)

            target = alert.get("target", "")
            summary = alert.get("summary", {})
            score = summary.get("riskScore", summary.get("globalRiskScore", 0))

            # Parse target: "npm/package-name@version" or "pypi/package@version"
            if "/" in target and "@" in target:
                eco_pkg = target.split("/", 1)
                if len(eco_pkg) == 2:
                    pkg_ver = eco_pkg[1]
                    # Determine tier from priority
                    priority = alert.get("priority", {})
                    tier = ""
                    p_level = priority.get("level", "")
                    if p_level == "P1":
                        tier = "T1a"
                    elif p_level == "P2":
                        tier = "T1b"
                    elif p_level == "P3":
                        tier = "T2"

                    scores[pkg_ver] = {"score": score, "tier": tier}

        except (json.JSONDecodeError, OSError):
            continue

    # Cache for next run
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump({"count": len(scores), "built_at": datetime.now(timezone.utc).isoformat(),
                    "scores": scores}, f)

    log.info("Extracted scores from %d alerts", len(scores))
    return scores


# ── Steps ──

def step_ossf():
    """Step 1: Index OSSF malicious-packages."""
    log.info("=== Step 1: OSSF Index ===")
    ossf_index.clone_or_update(OSSF_REPO_DIR)
    index = ossf_index.build_index(OSSF_REPO_DIR, CACHE_DIR)
    return index


def step_ghsa():
    """Step 3: Index GitHub Advisory Database."""
    log.info("=== Step 3: GHSA Index ===")
    # Try cache first
    index = ghsa_checker.load_cached_index(CACHE_DIR)
    if index is not None:
        return index
    return ghsa_checker.build_index(CACHE_DIR)


def step_npm(detections):
    """Step 2: Check npm status for suspects."""
    log.info("=== Step 2: npm Status Check ===")
    return npm_checker.check_suspects(detections, CACHE_DIR)


def step_label(detections, o_index, g_index, npm_status, alert_scores):
    """Step 4: Generate labels."""
    log.info("=== Step 4: Generate Labels ===")

    labels = labeler.label_suspects(detections, o_index, g_index, npm_status, alert_scores)
    missed = labeler.find_missed(o_index, g_index, detections)
    summary = labeler.export_labels(labels, missed, OUTPUT_PATH)

    return summary


# ── Modes ──

def run_full():
    """Run all steps sequentially."""
    log.info("Starting full auto-labeling pipeline")
    start = datetime.now()

    detections = load_detections()
    alert_scores = load_alert_scores()

    # Steps 1+3 don't depend on detections — could be parallel but keep it simple
    o_index = step_ossf()
    g_index = step_ghsa()
    npm_status = step_npm(detections)

    summary = step_label(detections, o_index, g_index, npm_status, alert_scores)

    elapsed = (datetime.now() - start).total_seconds()
    log.info("Pipeline complete in %.1fs — %s", elapsed, summary)
    return summary


def run_update():
    """Cron mode: re-check pending/unconfirmed labels against fresh external data."""
    log.info("Starting update (cron mode)")

    # Refresh external indices
    ossf_index.clone_or_update(OSSF_REPO_DIR)
    o_index = ossf_index.build_index(OSSF_REPO_DIR, CACHE_DIR)
    g_index = ghsa_checker.build_index(CACHE_DIR)

    # Load existing labels
    if not OUTPUT_PATH.is_file():
        log.error("No existing auto-labels.json — run --full first")
        sys.exit(1)

    with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
        existing = json.load(f)

    existing_labels = existing.get("labels", {})
    detections = load_detections()
    alert_scores = load_alert_scores()

    # Find labels that need re-evaluation
    to_recheck = []
    for key, entry in existing_labels.items():
        lbl = entry.get("auto_label")
        if lbl in ("pending", "unconfirmed", "likely_malicious"):
            # Re-extract detection info
            for det in detections:
                if f"{det['package']}@{det['version']}" == key:
                    to_recheck.append(det)
                    break

    if not to_recheck:
        log.info("No pending/unconfirmed labels to re-check")
        return

    log.info("Re-checking %d labels (pending/unconfirmed/likely_malicious)", len(to_recheck))

    # Re-check npm status for these specific packages
    npm_status = npm_checker.check_suspects(to_recheck, CACHE_DIR)

    # Re-label
    updated = labeler.label_suspects(to_recheck, o_index, g_index, npm_status, alert_scores)

    # Merge updates into existing labels
    changes = 0
    for key, new_entry in updated.items():
        old = existing_labels.get(key, {})
        if old.get("auto_label") != new_entry.get("auto_label"):
            log.info("RELABEL: %s — %s → %s",
                     key, old.get("auto_label"), new_entry.get("auto_label"))
            changes += 1
        existing_labels[key] = new_entry

    # Also refresh missed detection
    missed = labeler.find_missed(o_index, g_index, detections)
    for name, info in missed.items():
        mk = f"{name}@*"
        if mk not in existing_labels:
            existing_labels[mk] = info
            changes += 1

    # Re-export
    labeler.export_labels(
        {k: v for k, v in existing_labels.items() if v.get("auto_label") != "missed"},
        {k.replace("@*", ""): v for k, v in existing_labels.items() if v.get("auto_label") == "missed"},
        OUTPUT_PATH,
    )

    log.info("Update complete: %d labels changed", changes)


def main():
    parser = argparse.ArgumentParser(description="MUAD'DIB Auto-Labeling Pipeline")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--full", action="store_true", help="Run all steps")
    group.add_argument("--step", choices=["ossf", "ghsa", "npm", "label"],
                       help="Run individual step")
    group.add_argument("--update", action="store_true",
                       help="Cron: re-check pending/unconfirmed")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    parser.add_argument("--data-dir", help="Override MUADDIB_DATA path")
    parser.add_argument("--alerts-dir", help="Override MUADDIB_ALERTS path")
    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.data_dir:
        global MUADDIB_DATA, OUTPUT_PATH
        MUADDIB_DATA = Path(args.data_dir)
        OUTPUT_PATH = MUADDIB_DATA / "auto-labels.json"
    if args.alerts_dir:
        global MUADDIB_ALERTS
        MUADDIB_ALERTS = Path(args.alerts_dir)

    if args.full:
        run_full()
    elif args.update:
        run_update()
    elif args.step == "ossf":
        step_ossf()
    elif args.step == "ghsa":
        step_ghsa()
    elif args.step == "npm":
        step_npm(load_detections())
    elif args.step == "label":
        detections = load_detections()
        alert_scores = load_alert_scores()
        o_index = ossf_index.load_cached_index(CACHE_DIR)
        g_index = ghsa_checker.load_cached_index(CACHE_DIR)
        npm_status = npm_checker._load_cache(CACHE_DIR / npm_checker.CACHE_FILENAME)
        if o_index is None or g_index is None:
            log.error("Run --step ossf and --step ghsa first (or use --full)")
            sys.exit(1)
        step_label(detections, o_index, g_index, npm_status, alert_scores)


if __name__ == "__main__":
    main()
