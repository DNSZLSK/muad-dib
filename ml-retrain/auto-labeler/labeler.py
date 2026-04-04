"""
Label generation engine.

Correlates signals from OSSF, GHSA, and npm status to produce labels.

Label tiers (by confidence):
- confirmed_malicious: authoritative source (ossf/ghsa) OR npm takedown pattern
- likely_malicious:     npm_removed + high muaddib score, but no authoritative confirmation
- unconfirmed:          suspect in muaddib, still on npm, no external signal, >7 days old
- pending:              suspect in muaddib, still on npm, no external signal, <7 days old
- missed:               clean in muaddib BUT flagged by ossf/ghsa (false negative)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ossf_index import lookup as ossf_lookup
from ghsa_checker import lookup as ghsa_lookup
from npm_checker import is_quick_takedown

log = logging.getLogger("auto-labeler.labeler")

# Thresholds
SCORE_THRESHOLD_CONFIRMED = 50  # Minimum muaddib score for npm_removed → confirmed
PENDING_DAYS = 7  # Days before pending → unconfirmed


def _parse_iso(s):
    """Parse ISO 8601 date string to datetime."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _days_since(iso_str):
    """Days elapsed since the given ISO date string."""
    dt = _parse_iso(iso_str)
    if not dt:
        return None
    delta = datetime.now(timezone.utc) - dt
    return delta.total_seconds() / 86400


def _severity_to_score_estimate(severity):
    """Rough score estimate from severity when exact score is unavailable."""
    return {"CRITICAL": 70, "HIGH": 40, "MEDIUM": 15, "LOW": 5}.get(severity, 0)


def label_suspects(detections, ossf_index, ghsa_index, npm_status, alert_scores):
    """Generate labels for all suspect detections.

    Args:
        detections: list of detection dicts from detections.json
        ossf_index: dict from ossf_index.build_index()
        ghsa_index: dict from ghsa_checker.build_index()
        npm_status: dict from npm_checker.check_suspects()
        alert_scores: dict keyed by "name@version" with {"score": N, "tier": "T1a"} from alerts

    Returns:
        dict keyed by "name@version" with label info
    """
    labels = {}
    stats = {"confirmed_malicious": 0, "likely_malicious": 0,
             "unconfirmed": 0, "pending": 0}

    for det in detections:
        name = det["package"]
        version = det["version"]
        ecosystem = det.get("ecosystem", "npm")
        key = f"{name}@{version}"
        detection_date = det.get("first_seen_at", "")
        severity = det.get("severity", "UNKNOWN")
        findings = det.get("findings", [])

        # Skip non-npm for now (OSSF/GHSA npm-focused)
        if ecosystem != "npm":
            continue

        # Gather signals
        signals = []

        # Signal 1: OSSF
        ossf_hit = ossf_lookup(ossf_index, name, version)
        if ossf_hit:
            signals.append("ossf")

        # Signal 2: GHSA
        ghsa_hit = ghsa_lookup(ghsa_index, name)
        if ghsa_hit:
            signals.append("ghsa")

        # Signal 3: npm status
        npm_result = npm_status.get(key, {})
        npm_removed = npm_result.get("status") == "npm_removed"
        if npm_removed:
            signals.append("npm_removed")

        # Get score from alerts or estimate from severity
        score_info = alert_scores.get(key, {})
        score = score_info.get("score", _severity_to_score_estimate(severity))
        tier = score_info.get("tier", "")

        # Determine label
        label = _classify(signals, npm_result, detection_date, score)
        stats[label] += 1

        labels[key] = {
            "muaddib_label": "suspect",
            "auto_label": label,
            "signals": signals,
            "muaddib_score": score,
            "muaddib_tier": tier,
            "muaddib_severity": severity,
            "muaddib_findings": findings,
            "detection_date": detection_date,
            "label_date": datetime.now(timezone.utc).isoformat(),
            "npm_status": npm_result.get("status", "unknown"),
            "npm_publish_date": npm_result.get("publish_date"),
        }

        if ossf_hit:
            labels[key]["ossf_id"] = ossf_hit.get("osv_id")
        if ghsa_hit:
            labels[key]["ghsa_id"] = ghsa_hit[0].get("ghsa_id")

        log.debug("LABEL %s → %s (signals=%s, score=%d)", key, label, signals, score)

    log.info("Suspect labels: %s", stats)
    return labels


def _classify(signals, npm_result, detection_date, score):
    """Core classification logic."""
    has_authoritative = "ossf" in signals or "ghsa" in signals
    npm_removed = "npm_removed" in signals

    # Tier 1: Authoritative source confirms malicious
    if has_authoritative:
        return "confirmed_malicious"

    # Tier 2: npm takedown pattern (removed + high score + quick removal)
    if npm_removed and score >= SCORE_THRESHOLD_CONFIRMED:
        if is_quick_takedown(npm_result, detection_date, threshold_hours=72):
            return "confirmed_malicious"

    # Tier 3: npm removed but doesn't meet confirmation criteria
    if npm_removed:
        return "likely_malicious"

    # Tier 4: Still on npm, no external signal
    days = _days_since(detection_date)
    if days is not None and days > PENDING_DAYS:
        return "unconfirmed"

    return "pending"


def find_missed(ossf_index, ghsa_index, detections):
    """Find packages in OSSF/GHSA that muaddib did NOT detect (false negatives).

    Returns dict keyed by package name with miss details.
    """
    # Build set of all detected package names
    detected_names = set()
    for det in detections:
        if det.get("ecosystem") == "npm":
            detected_names.add(det["package"])

    missed = {}

    # Check OSSF index
    ossf_packages = set()
    for key in ossf_index:
        name = key.rsplit("@", 1)[0]
        ossf_packages.add(name)

    for name in ossf_packages:
        if name not in detected_names:
            missed[name] = {
                "auto_label": "missed",
                "muaddib_label": "clean",
                "signals": ["ossf"],
                "source_detail": "In ossf/malicious-packages but not in muaddib detections",
                "label_date": datetime.now(timezone.utc).isoformat(),
            }

    # Check GHSA index
    for name, entries in ghsa_index.items():
        if name not in detected_names:
            existing = missed.get(name)
            if existing:
                existing["signals"].append("ghsa")
            else:
                missed[name] = {
                    "auto_label": "missed",
                    "muaddib_label": "clean",
                    "signals": ["ghsa"],
                    "ghsa_id": entries[0].get("ghsa_id") if entries else None,
                    "source_detail": "In GHSA malware advisories but not in muaddib detections",
                    "label_date": datetime.now(timezone.utc).isoformat(),
                }

    log.info("Missed packages (false negatives): %d", len(missed))
    if missed:
        # Log the first 20 as these are critical for improving the scanner
        for name in list(missed.keys())[:20]:
            m = missed[name]
            log.warning("MISSED: %s (signals=%s)", name, m["signals"])

    return missed


def export_labels(labels, missed, output_path):
    """Export all labels to auto-labels.json."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Merge suspects and missed into one output
    all_labels = dict(labels)
    for name, info in missed.items():
        all_labels[f"{name}@*"] = info

    # Generate summary
    summary = {"confirmed_malicious": 0, "likely_malicious": 0,
               "unconfirmed": 0, "pending": 0, "missed": 0}
    for entry in all_labels.values():
        lbl = entry.get("auto_label", "unknown")
        if lbl in summary:
            summary[lbl] += 1

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "total": len(all_labels),
        "labels": all_labels,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    log.info("Exported %d labels to %s", len(all_labels), output_path)
    log.info("Summary: %s", summary)

    return summary
