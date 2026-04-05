#!/usr/bin/env python3
"""
MUAD'DIB ML Retrain — Auto-Label Ground Truth

Builds training dataset by crossing auto-labels.json with ml-training-merged.jsonl,
adds Datadog malicious corpus, trains XGBoost with grid search, exports model + report.

Usage:
    python ml-retrain/retrain.py --full
    python ml-retrain/retrain.py --build-dataset    # Step 1 only
    python ml-retrain/retrain.py --train-only        # Skip dataset build, use cached

Environment:
    MUADDIB_DATA    Override data directory (default: /opt/muaddib/data)
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, ParameterGrid
from sklearn.metrics import (
    precision_score, recall_score, f1_score, confusion_matrix,
    roc_auc_score, precision_recall_curve, roc_curve
)
import xgboost as xgb

# ── Paths ──
MUADDIB_DATA = Path(os.environ.get("MUADDIB_DATA", "/opt/muaddib/data"))
MUADDIB_ALERTS = MUADDIB_DATA.parent / "logs" / "alerts"
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR
DATASET_CACHE = OUTPUT_DIR / "retrain-dataset.jsonl"
REPORT_PATH = OUTPUT_DIR / "retrain-report.json"
MODEL_OUTPUT = OUTPUT_DIR / "model-trees-retrained.js"
CONFUSION_MATRIX_PATH = OUTPUT_DIR / "confusion-matrix.png"

# ── 87 hardcoded features — exact copy from train-xgboost.py ──
IDENTITY_COLS = {'name', 'version', 'ecosystem', 'timestamp', 'label', 'tier'}
FEATURE_NAMES = [
    'score', 'max_file_score', 'package_score', 'global_risk_score',
    'count_total', 'count_critical', 'count_high', 'count_medium', 'count_low',
    'distinct_threat_types',
    'type_suspicious_dataflow', 'type_env_access', 'type_sensitive_string',
    'type_dangerous_call_eval', 'type_dangerous_call_exec',
    'type_dangerous_call_function', 'type_obfuscation_detected',
    'type_high_entropy_string', 'type_dynamic_require', 'type_dynamic_import',
    'type_lifecycle_script', 'type_typosquat_detected', 'type_staged_payload',
    'type_staged_binary_payload', 'type_network_require', 'type_sandbox_evasion',
    'type_credential_regex_harvest', 'type_remote_code_load',
    'type_suspicious_domain', 'type_prototype_hook',
    'type_intent_credential_exfil', 'type_intent_command_exfil',
    'type_cross_file_dataflow', 'type_module_compile', 'type_crypto_decipher',
    'type_env_charcode_reconstruction', 'type_lifecycle_shell_pipe',
    'type_curl_exec', 'type_reverse_shell', 'type_binary_dropper',
    'type_mcp_config_injection',
    'type_vm_code_execution', 'type_vm_dynamic_code',
    'type_dangerous_constructor', 'type_module_load_bypass',
    'type_require_process_mainmodule', 'type_proxy_globalthis_intercept',
    'type_reflect_bind_code_execution',
    'type_known_malicious_package', 'type_known_malicious_hash',
    'type_unicode_invisible_injection', 'type_blockchain_c2_resolution',
    'type_dangerous_exec', 'type_node_inline_exec',
    'type_js_obfuscation_pattern',
    'type_suspicious_module_sink', 'type_wasm_host_sink',
    'type_other',
    'has_lifecycle_script', 'has_network_access', 'has_obfuscation',
    'has_env_access', 'has_eval', 'has_staged_payload', 'has_typosquat',
    'has_ioc_match', 'has_intent_pair', 'has_sandbox_finding',
    'file_count_with_threats', 'file_score_mean', 'file_score_max',
    'severity_ratio_high', 'max_single_points', 'points_concentration',
    'unpacked_size_bytes', 'dep_count', 'dev_dep_count',
    'reputation_factor',
    'package_age_days', 'weekly_downloads', 'version_count',
    'author_package_count', 'has_repository', 'readme_size',
    'file_count_total', 'has_tests', 'threat_density',
]
assert len(FEATURE_NAMES) == 87

# ── Grid search param space ──
PARAM_GRID = {
    'max_depth': [4, 6, 8],
    'n_estimators': [100, 200, 300],
    'learning_rate': [0.05, 0.1, 0.2],
}

XGB_BASE_PARAMS = {
    'objective': 'binary:logistic',
    'eval_metric': 'logloss',
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'min_child_weight': 5,
    'gamma': 0.1,
    'reg_alpha': 0.1,
    'reg_lambda': 1.0,
    'seed': 42,
    'verbosity': 0,
}


# ── TOP_THREAT_TYPES — mirrors feature-extractor.js ──
TOP_THREAT_TYPES = [
    'suspicious_dataflow', 'env_access', 'sensitive_string',
    'dangerous_call_eval', 'dangerous_call_exec', 'dangerous_call_function',
    'obfuscation_detected', 'high_entropy_string', 'dynamic_require',
    'dynamic_import', 'lifecycle_script', 'typosquat_detected', 'staged_payload',
    'staged_binary_payload', 'network_require', 'sandbox_evasion',
    'credential_regex_harvest', 'remote_code_load', 'suspicious_domain',
    'prototype_hook', 'intent_credential_exfil', 'intent_command_exfil',
    'cross_file_dataflow', 'module_compile', 'crypto_decipher',
    'env_charcode_reconstruction', 'lifecycle_shell_pipe', 'curl_exec',
    'reverse_shell', 'binary_dropper', 'mcp_config_injection',
    'vm_code_execution', 'vm_dynamic_code', 'dangerous_constructor',
    'module_load_bypass', 'require_process_mainmodule',
    'proxy_globalthis_intercept', 'reflect_bind_code_execution',
    'known_malicious_package', 'known_malicious_hash',
    'unicode_invisible_injection', 'blockchain_c2_resolution',
    'dangerous_exec', 'node_inline_exec', 'js_obfuscation_pattern',
    'suspicious_module_sink', 'wasm_host_sink',
]
TOP_THREAT_TYPES_SET = set(TOP_THREAT_TYPES)


def extract_features_from_alert(alert):
    """Extract the 87 ML features from an alert JSON file.

    Python port of feature-extractor.js — used to recover feature vectors
    for confirmed_malicious packages that have alert files but no JSONL record.
    Registry metadata features will be 0 (not available in alerts).
    """
    feat = {}
    summary = alert.get("summary", {})
    threats = alert.get("threats", [])

    # Scoring
    feat['score'] = summary.get('riskScore', 0)
    feat['max_file_score'] = summary.get('maxFileScore', 0)
    feat['package_score'] = summary.get('packageScore', 0)
    feat['global_risk_score'] = summary.get('globalRiskScore', 0)

    # Severity counts
    feat['count_total'] = summary.get('total', 0)
    feat['count_critical'] = summary.get('critical', 0)
    feat['count_high'] = summary.get('high', 0)
    feat['count_medium'] = summary.get('medium', 0)
    feat['count_low'] = summary.get('low', 0)

    # Distinct threat types
    distinct = set(t.get('type', '') for t in threats if t.get('type'))
    feat['distinct_threat_types'] = len(distinct)

    # Per-type counts
    type_counts = {}
    for t in threats:
        tt = t.get('type', '')
        if tt:
            type_counts[tt] = type_counts.get(tt, 0) + 1
    for tt in TOP_THREAT_TYPES:
        feat[f'type_{tt}'] = type_counts.get(tt, 0)
    other = sum(c for tt, c in type_counts.items() if tt not in TOP_THREAT_TYPES_SET)
    feat['type_other'] = other

    # Boolean behavioral signals
    types_set = set(type_counts.keys())
    feat['has_lifecycle_script'] = int(bool(types_set & {'lifecycle_script', 'lifecycle_shell_pipe'}))
    feat['has_network_access'] = int(bool(types_set & {'network_require', 'remote_code_load', 'curl_exec', 'suspicious_dataflow'}))
    feat['has_obfuscation'] = int(bool(types_set & {'obfuscation_detected', 'high_entropy_string', 'js_obfuscation_pattern'}))
    feat['has_env_access'] = int(bool(types_set & {'env_access', 'env_charcode_reconstruction'}))
    feat['has_eval'] = int(bool(types_set & {'dangerous_call_eval', 'dangerous_call_function'}))
    feat['has_staged_payload'] = int(bool(types_set & {'staged_payload', 'staged_binary_payload'}))
    feat['has_typosquat'] = int(bool(types_set & {'typosquat_detected', 'pypi_typosquat_detected'}))
    feat['has_ioc_match'] = int(bool(types_set & {'known_malicious_package', 'known_malicious_hash', 'pypi_malicious_package', 'dependency_ioc_match'}))
    feat['has_intent_pair'] = int(bool(types_set & {'intent_credential_exfil', 'intent_command_exfil'}))
    feat['has_sandbox_finding'] = int(any(tt.startswith('sandbox_') for tt in types_set))

    # File distribution
    file_scores = summary.get('fileScores', {})
    vals = list(file_scores.values()) if isinstance(file_scores, dict) else []
    feat['file_count_with_threats'] = len(vals)
    feat['file_score_mean'] = round(sum(vals) / len(vals)) if vals else 0
    feat['file_score_max'] = max(vals) if vals else 0

    # Severity concentration
    feat['severity_ratio_high'] = round(
        (feat['count_critical'] + feat['count_high']) / max(feat['count_total'], 1), 2)
    breakdown = summary.get('breakdown', [])
    feat['max_single_points'] = breakdown[0].get('points', 0) if breakdown else 0
    feat['points_concentration'] = round(
        feat['max_single_points'] / max(feat['score'], 1), 2) if feat['score'] > 0 else 0

    # Package metadata — not available in alerts, default to 0
    feat['unpacked_size_bytes'] = 0
    feat['dep_count'] = 0
    feat['dev_dep_count'] = 0
    feat['reputation_factor'] = 1.0
    feat['package_age_days'] = 0
    feat['weekly_downloads'] = 0
    feat['version_count'] = 0
    feat['author_package_count'] = 0
    feat['has_repository'] = 0
    feat['readme_size'] = 0
    feat['file_count_total'] = 0
    feat['has_tests'] = 0
    feat['threat_density'] = round(
        feat['count_total'] / max(feat['file_count_with_threats'], 1), 2)

    return feat


def load_alert_index(alerts_dir):
    """Build index of alert files keyed by 'name@version'.

    Returns dict: { "name@version": alert_dict }
    """
    alerts_dir = Path(alerts_dir)
    if not alerts_dir.is_dir():
        return {}

    index = {}
    for filepath in alerts_dir.glob("*.json"):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                alert = json.load(f)
            target = alert.get("target", "")
            # target format: "npm/package-name@version"
            if "/" in target and "@" in target:
                pkg_ver = target.split("/", 1)[1]  # "name@version"
                # Keep the alert with the highest score for each package
                existing = index.get(pkg_ver)
                new_score = alert.get("summary", {}).get("riskScore", 0)
                if existing is None or new_score > existing.get("summary", {}).get("riskScore", 0):
                    index[pkg_ver] = alert
        except (json.JSONDecodeError, OSError):
            continue

    return index


# ══════════════════════════════════════════════════════════════
# Step 1: Build training dataset
# ══════════════════════════════════════════════════════════════

def load_jsonl(filepath):
    """Load JSONL, skip malformed lines."""
    records = []
    skipped = 0
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1
                print(f"  [WARN] Skipping malformed line {line_num} in {filepath}")
    return records, skipped


def build_dataset():
    """Cross auto-labels.json with ml-training-merged.jsonl + Datadog corpus."""
    print("=" * 70)
    print("[Step 1] Building training dataset from auto-labels + merged JSONL")
    print("=" * 70)

    # Load auto-labels
    auto_labels_path = MUADDIB_DATA / "auto-labels.json"
    if not auto_labels_path.is_file():
        print(f"ERROR: {auto_labels_path} not found", file=sys.stderr)
        sys.exit(1)

    with open(auto_labels_path, 'r', encoding='utf-8') as f:
        auto_labels = json.load(f)
    labels_map = auto_labels.get("labels", {})
    print(f"  Auto-labels loaded: {len(labels_map)} entries")
    print(f"  Summary: {auto_labels.get('summary', {})}")

    # Load merged JSONL
    merged_path = MUADDIB_DATA / "ml-training-merged.jsonl"
    if not merged_path.is_file():
        print(f"ERROR: {merged_path} not found", file=sys.stderr)
        sys.exit(1)

    merged_records, merged_skipped = load_jsonl(merged_path)
    print(f"  Merged JSONL: {len(merged_records)} records ({merged_skipped} corrupted, skipped)")

    # Load Datadog malicious
    datadog_path = MUADDIB_DATA / "ml-training-datadog-full.jsonl"
    if not datadog_path.is_file():
        print(f"ERROR: {datadog_path} not found", file=sys.stderr)
        sys.exit(1)

    datadog_records, datadog_skipped = load_jsonl(datadog_path)
    print(f"  Datadog JSONL: {len(datadog_records)} records ({datadog_skipped} corrupted, skipped)")

    # Load alert index for recovering confirmed_malicious without JSONL records
    alert_index = load_alert_index(MUADDIB_ALERTS)
    print(f"  Alert index: {len(alert_index)} packages")

    # Cross merged records with auto-labels
    dataset = []
    stats = {
        "confirmed_malicious_jsonl": 0,
        "confirmed_malicious_alert": 0,
        "confirmed_malicious_no_features": 0,
        "likely_malicious_excluded": 0,
        "unconfirmed_as_clean": 0,
        "pending_excluded": 0,
        "clean_no_match": 0,
        "datadog_malicious": 0,
    }

    seen = set()  # (name, version) dedup

    for rec in merged_records:
        name = rec.get("name", "")
        version = rec.get("version", "")
        key = f"{name}@{version}"
        dedup_key = (name, version)

        if dedup_key in seen:
            continue

        auto = labels_map.get(key, {})
        auto_label = auto.get("auto_label", "")

        if auto_label == "confirmed_malicious":
            rec["label"] = "malicious"
            rec["_retrain_source"] = "auto-label:confirmed+jsonl"
            dataset.append(rec)
            stats["confirmed_malicious_jsonl"] += 1
            seen.add(dedup_key)

        elif auto_label == "unconfirmed":
            # Suspect not confirmed after 7+ days → treat as clean for training
            rec["label"] = "clean"
            rec["_retrain_source"] = "auto-label:unconfirmed"
            dataset.append(rec)
            stats["unconfirmed_as_clean"] += 1
            seen.add(dedup_key)

        elif auto_label == "likely_malicious":
            # Exclude from training — ambiguous signal
            stats["likely_malicious_excluded"] += 1
            seen.add(dedup_key)
            continue

        elif auto_label == "pending":
            # Exclude — too recent for reliable label
            stats["pending_excluded"] += 1
            seen.add(dedup_key)
            continue

        else:
            # No match in auto-labels — use original label
            orig_label = rec.get("label", "")
            if orig_label in ("clean", "fp", "ml_clean"):
                rec["label"] = "clean"
                rec["_retrain_source"] = f"original:{orig_label}"
                dataset.append(rec)
                stats["clean_no_match"] += 1
                seen.add(dedup_key)
            # Skip suspect/unconfirmed/unknown without auto-label match

    # Add Datadog malicious corpus
    for rec in datadog_records:
        name = rec.get("name", "")
        version = rec.get("version", "")
        dedup_key = (name, version)

        if dedup_key in seen:
            continue

        rec["label"] = "malicious"
        rec["_retrain_source"] = "datadog"
        dataset.append(rec)
        stats["datadog_malicious"] += 1
        seen.add(dedup_key)

    # Recover confirmed_malicious that have alert files but no JSONL record
    for key, label_info in labels_map.items():
        if label_info.get("auto_label") != "confirmed_malicious":
            continue
        # key is "name@version"
        if "@" not in key:
            continue
        name, version = key.rsplit("@", 1)
        dedup_key = (name, version)
        if dedup_key in seen:
            continue

        alert = alert_index.get(key)
        if alert:
            features = extract_features_from_alert(alert)
            rec = {
                "name": name, "version": version, "ecosystem": "npm",
                "label": "malicious",
                "_retrain_source": "auto-label:confirmed+alert",
            }
            rec.update(features)
            dataset.append(rec)
            stats["confirmed_malicious_alert"] += 1
        else:
            stats["confirmed_malicious_no_features"] += 1

        seen.add(dedup_key)

    print(f"\n  Dataset construction:")
    for k, v in stats.items():
        print(f"    {k}: {v}")

    n_malicious = sum(1 for r in dataset if r["label"] == "malicious")
    n_clean = sum(1 for r in dataset if r["label"] == "clean")
    print(f"\n  Final dataset: {len(dataset)} samples")
    print(f"    Malicious: {n_malicious}")
    print(f"    Clean: {n_clean}")
    print(f"    Ratio (clean/malicious): {n_clean / max(n_malicious, 1):.2f}")

    # Cache dataset
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(DATASET_CACHE, 'w', encoding='utf-8') as f:
        for rec in dataset:
            f.write(json.dumps(rec, separators=(',', ':')) + '\n')
    print(f"  Cached to {DATASET_CACHE}")

    return dataset, stats


# ══════════════════════════════════════════════════════════════
# Step 2: Feature alignment
# ══════════════════════════════════════════════════════════════

def align_features(dataset):
    """Align dataset to 87 features, return X, y.

    All missing features use 0 (not -1) to prevent data leakage:
    XGBoost learns split directions for missing values, so -1 in one source
    and real values in another creates a perfect source-identity signal.
    """
    print("\n" + "=" * 70)
    print("[Step 2] Aligning 87 features (0 for missing — no leakage)")
    print("=" * 70)

    X_data = []
    y_data = []

    for rec in dataset:
        row = []
        for feat in FEATURE_NAMES:
            val = rec.get(feat, 0)
            if val is None:
                val = 0
            row.append(float(val))
        X_data.append(row)
        y_data.append(1 if rec["label"] == "malicious" else 0)

    X = pd.DataFrame(X_data, columns=FEATURE_NAMES)
    y = np.array(y_data, dtype=int)

    print(f"  Feature matrix: {X.shape[0]} x {X.shape[1]}")
    print(f"  Class distribution: {int((y == 0).sum())} clean, {int((y == 1).sum())} malicious")

    return X, y


def filter_leaky_features(X, y, min_coverage=0.001):
    """Remove dead features AND source-identity leaks.

    A feature is dropped if:
    - DEAD: non-zero in < 0.1% of ALL samples
    - LEAKY: non-zero in >= 99% of one class AND < 0.1% of the other
      (proxy for data source, not malware signal)

    Ported from train-xgboost.py filter_leaky_features().
    """
    print("\n" + "=" * 70)
    print("[Step 2b] Filtering dead / leaky features")
    print("=" * 70)

    neg_mask = y == 0
    pos_mask = y == 1
    n_neg = int(neg_mask.sum())
    n_pos = int(pos_mask.sum())
    n_total = n_neg + n_pos

    active = []
    dead = []
    leaky = []

    for feat in FEATURE_NAMES:
        neg_nz = float((X.loc[neg_mask, feat] != 0).sum()) / max(n_neg, 1)
        pos_nz = float((X.loc[pos_mask, feat] != 0).sum()) / max(n_pos, 1)
        all_nz = float((X[feat] != 0).sum()) / max(n_total, 1)

        if all_nz < min_coverage:
            dead.append(feat)
        elif (neg_nz >= 0.99 and pos_nz < min_coverage):
            leaky.append(feat)
        elif (pos_nz >= 0.99 and neg_nz < min_coverage):
            leaky.append(feat)
        else:
            active.append(feat)

    if dead:
        print(f"  DEAD ({len(dead)}): {', '.join(dead)}")
    if leaky:
        print(f"  LEAKY ({len(leaky)}): {', '.join(leaky)}")
    print(f"  Active: {len(active)} / {len(FEATURE_NAMES)}")

    return X[active], active


# ══════════════════════════════════════════════════════════════
# Step 3: Grid search + training
# ══════════════════════════════════════════════════════════════

def grid_search(X_train, y_train, active_features, scale_pos_weight):
    """Grid search over hyperparameters with 3-fold CV for speed."""
    print("\n" + "=" * 70)
    print("[Step 3] Grid search (3-fold CV)")
    print("=" * 70)

    param_combinations = list(ParameterGrid(PARAM_GRID))
    print(f"  {len(param_combinations)} combinations to evaluate")

    skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    best_f1 = 0
    best_params = None
    results = []

    for i, params in enumerate(param_combinations):
        xgb_params = {
            **XGB_BASE_PARAMS,
            'max_depth': params['max_depth'],
            'learning_rate': params['learning_rate'],
            'scale_pos_weight': scale_pos_weight,
        }
        n_est = params['n_estimators']

        fold_f1s = []
        for train_idx, val_idx in skf.split(X_train, y_train):
            X_tr = X_train.iloc[train_idx]
            X_va = X_train.iloc[val_idx]
            y_tr = y_train[train_idx]
            y_va = y_train[val_idx]

            dtrain = xgb.DMatrix(X_tr, label=y_tr, feature_names=active_features)
            dval = xgb.DMatrix(X_va, label=y_va, feature_names=active_features)

            model = xgb.train(
                xgb_params, dtrain, num_boost_round=n_est,
                evals=[(dval, 'val')], verbose_eval=False,
                early_stopping_rounds=20
            )

            probs = model.predict(dval)
            preds = (probs >= 0.5).astype(int)
            fold_f1s.append(f1_score(y_va, preds, zero_division=0))

        mean_f1 = np.mean(fold_f1s)
        results.append({**params, 'mean_f1': mean_f1})

        marker = " ← BEST" if mean_f1 > best_f1 else ""
        if mean_f1 > best_f1:
            best_f1 = mean_f1
            best_params = params

        if (i + 1) % 9 == 0 or i == 0 or mean_f1 > best_f1 - 0.001:
            print(f"  [{i + 1:2d}/{len(param_combinations)}] "
                  f"depth={params['max_depth']} est={params['n_estimators']} "
                  f"lr={params['learning_rate']} → F1={mean_f1:.4f}{marker}")

    print(f"\n  Best params: {best_params} (F1={best_f1:.4f})")

    # Sort all results by F1
    results.sort(key=lambda x: x['mean_f1'], reverse=True)

    return best_params, results


def train_final(X_train, y_train, active_features, best_params, scale_pos_weight):
    """Train final model with best params on full training set."""
    print("\n" + "=" * 70)
    print("[Step 4] Training final model with best params")
    print("=" * 70)

    xgb_params = {
        **XGB_BASE_PARAMS,
        'max_depth': best_params['max_depth'],
        'learning_rate': best_params['learning_rate'],
        'scale_pos_weight': scale_pos_weight,
    }

    # Internal 90/10 for early stopping
    X_tr, X_es, y_tr, y_es = train_test_split(
        X_train, y_train, test_size=0.1, stratify=y_train, random_state=42
    )

    dtrain = xgb.DMatrix(X_tr, label=y_tr, feature_names=active_features)
    des = xgb.DMatrix(X_es, label=y_es, feature_names=active_features)

    model = xgb.train(
        xgb_params, dtrain, num_boost_round=best_params['n_estimators'],
        evals=[(des, 'early_stop')], verbose_eval=False,
        early_stopping_rounds=20
    )

    best_round = getattr(model, 'best_iteration', best_params['n_estimators'])
    print(f"  Best iteration: {best_round}")

    return model


def optimize_threshold(model, X_train, y_train, active_features,
                       best_params=None, scale_pos_weight=1.0):
    """5-fold CV to find optimal threshold (maximize precision at recall >= 93.9%)."""
    print("\n" + "=" * 70)
    print("[Step 5] Threshold optimization (5-fold CV, recall >= 93.9%)")
    print("=" * 70)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    all_probs = np.zeros(len(y_train))

    for fold, (train_idx, val_idx) in enumerate(skf.split(X_train, y_train)):
        X_tr = X_train.iloc[train_idx]
        X_va = X_train.iloc[val_idx]
        y_tr = y_train[train_idx]
        y_va = y_train[val_idx]

        dtrain = xgb.DMatrix(X_tr, label=y_tr, feature_names=active_features)
        dval = xgb.DMatrix(X_va, label=y_va, feature_names=active_features)

        fold_params = {
            **XGB_BASE_PARAMS,
            'max_depth': best_params['max_depth'],
            'learning_rate': best_params['learning_rate'],
            'scale_pos_weight': scale_pos_weight,
        }
        fold_model = xgb.train(
            fold_params,
            dtrain, num_boost_round=best_params['n_estimators'],
            evals=[(dval, 'val')], verbose_eval=False,
            early_stopping_rounds=20
        )
        all_probs[val_idx] = fold_model.predict(dval)

    # Sweep thresholds
    best_threshold = 0.5
    best_precision = 0.0

    for t in np.arange(0.10, 0.91, 0.01):
        preds = (all_probs >= t).astype(int)
        r = recall_score(y_train, preds, zero_division=0)
        p = precision_score(y_train, preds, zero_division=0)
        if r >= 0.939 and p > best_precision:
            best_precision = p
            best_threshold = float(t)

    if best_precision == 0.0:
        print("  [WARN] No threshold achieves recall >= 93.9%, using 0.5")
        best_threshold = 0.5

    preds = (all_probs >= best_threshold).astype(int)
    p = precision_score(y_train, preds, zero_division=0)
    r = recall_score(y_train, preds, zero_division=0)
    f1 = f1_score(y_train, preds, zero_division=0)

    print(f"  Optimal threshold: {best_threshold:.3f}")
    print(f"  CV metrics: P={p:.3f} R={r:.3f} F1={f1:.3f}")

    return best_threshold, {'precision': p, 'recall': r, 'f1': f1}


# ══════════════════════════════════════════════════════════════
# Step 6: Evaluate on holdout
# ══════════════════════════════════════════════════════════════

def evaluate_holdout(model, X_test, y_test, active_features, threshold):
    """Evaluate on held-out test set."""
    print("\n" + "=" * 70)
    print(f"[Step 6] Holdout evaluation (threshold={threshold:.3f})")
    print("=" * 70)

    dtest = xgb.DMatrix(X_test, label=y_test, feature_names=active_features)
    probs = model.predict(dtest)

    preds = (probs >= threshold).astype(int)
    p = precision_score(y_test, preds, zero_division=0)
    r = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    cm = confusion_matrix(y_test, preds)
    tn, fp_count, fn, tp = cm.ravel()

    # AUC-ROC
    try:
        auc = roc_auc_score(y_test, probs)
    except ValueError:
        auc = 0.0

    # FPR / TPR
    fpr = fp_count / max(fp_count + tn, 1)
    tpr = tp / max(tp + fn, 1)

    print(f"  Precision:  {p:.4f}")
    print(f"  Recall/TPR: {r:.4f}")
    print(f"  F1:         {f1:.4f}")
    print(f"  AUC-ROC:    {auc:.4f}")
    print(f"  FPR:        {fpr:.4f}")
    print(f"  Confusion matrix:")
    print(f"    TN={tn:>6d}  FP={fp_count:>6d}")
    print(f"    FN={fn:>6d}  TP={tp:>6d}")

    # Feature importance
    importance = model.get_score(importance_type='gain')
    sorted_imp = sorted(importance.items(), key=lambda x: x[1], reverse=True)
    print(f"\n  Top 20 features (gain):")
    for i, (name, val) in enumerate(sorted_imp[:20]):
        print(f"    {i + 1:2d}. {name:40s} {val:.4f}")

    return {
        'precision': round(float(p), 4),
        'recall': round(float(r), 4),
        'f1': round(float(f1), 4),
        'auc_roc': round(float(auc), 4),
        'fpr': round(float(fpr), 4),
        'tpr': round(float(tpr), 4),
        'confusion_matrix': cm.tolist(),
        'tp': int(tp), 'fp': int(fp_count),
        'fn': int(fn), 'tn': int(tn),
        'top_20_features': [(name, round(val, 4)) for name, val in sorted_imp[:20]],
    }, probs


# ══════════════════════════════════════════════════════════════
# Step 7: Export
# ══════════════════════════════════════════════════════════════

def save_confusion_matrix_png(y_test, preds, output_path):
    """Save confusion matrix as PNG."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        cm = confusion_matrix(y_test, preds)
        fig, ax = plt.subplots(figsize=(8, 6))
        im = ax.imshow(cm, interpolation='nearest', cmap='Blues')
        ax.figure.colorbar(im, ax=ax)

        classes = ['Clean (0)', 'Malicious (1)']
        ax.set(xticks=[0, 1], yticks=[0, 1],
               xticklabels=classes, yticklabels=classes,
               ylabel='True label', xlabel='Predicted label',
               title='MUAD\'DIB Retrained Model — Confusion Matrix')

        # Text annotations
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f'{cm[i, j]:,}',
                        ha='center', va='center',
                        color='white' if cm[i, j] > cm.max() / 2 else 'black',
                        fontsize=16)

        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        print(f"  Confusion matrix saved to {output_path}")
    except ImportError:
        print("  [WARN] matplotlib not available — skipping confusion matrix PNG")


def convert_tree(tree_json, nodes, feature_map):
    """Recursively convert XGBoost tree JSON to flat array (from train-xgboost.py)."""
    idx = len(nodes)
    nodes.append(None)

    if 'leaf' in tree_json:
        nodes[idx] = {'f': -1, 't': 0, 'y': 0, 'n': 0,
                       'v': round(tree_json['leaf'], 6)}
    else:
        split_feature = tree_json.get('split', '')
        feature_idx = feature_map.get(split_feature, -1)
        threshold = tree_json.get('split_condition', 0)
        children = tree_json.get('children', [])
        yes_child = tree_json.get('yes', 0)
        no_child = tree_json.get('no', 0)

        yes_tree = no_tree = None
        for child in children:
            if child.get('nodeid') == yes_child:
                yes_tree = child
            elif child.get('nodeid') == no_child:
                no_tree = child
        if yes_tree is None and len(children) > 0:
            yes_tree = children[0]
        if no_tree is None and len(children) > 1:
            no_tree = children[1]

        yes_idx = convert_tree(yes_tree, nodes, feature_map) if yes_tree else idx
        no_idx = convert_tree(no_tree, nodes, feature_map) if no_tree else idx

        nodes[idx] = {'f': feature_idx, 't': round(threshold, 6),
                       'y': yes_idx, 'n': no_idx, 'v': 0}
    return idx


def export_model_js(model, features, threshold, cv_metrics, holdout_metrics, output_path):
    """Export model to model-trees.js format."""
    print("\n" + "=" * 70)
    print(f"[Step 7] Exporting model to {output_path}")
    print("=" * 70)

    trees_dump = model.get_dump(dump_format='json')
    feature_map = {name: idx for idx, name in enumerate(features)}

    js_trees = []
    total_nodes = 0
    for tree_str in trees_dump:
        tree_json = json.loads(tree_str)
        nodes = []
        convert_tree(tree_json, nodes, feature_map)
        js_trees.append(nodes)
        total_nodes += len(nodes)

    js_model = {
        'version': 1,
        'features': features,
        'threshold': threshold,
        'trees': js_trees,
    }

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    js_content = "'use strict';\n\n"
    js_content += "/**\n"
    js_content += f" * XGBoost model trees — auto-generated by ml-retrain/retrain.py ({now})\n"
    js_content += f" * {len(js_trees)} trees, {len(features)} features, threshold={threshold}\n"
    js_content += f" * CV: P={cv_metrics['precision']:.3f} R={cv_metrics['recall']:.3f} F1={cv_metrics['f1']:.3f}\n"
    js_content += f" * Holdout: P={holdout_metrics['precision']:.3f} R={holdout_metrics['recall']:.3f} F1={holdout_metrics['f1']:.3f}\n"
    js_content += f" * AUC-ROC: {holdout_metrics['auc_roc']:.3f}\n"
    js_content += " * DO NOT EDIT MANUALLY\n"
    js_content += " */\n\n"
    js_content += f"module.exports = {json.dumps(js_model, separators=(',', ':'))};\n"

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(js_content)

    size_kb = output_path.stat().st_size / 1024
    print(f"  Trees: {len(js_trees)}, nodes: {total_nodes}")
    print(f"  Features: {len(features)}, threshold: {threshold:.3f}")
    print(f"  File: {size_kb:.1f} KB")


def save_report(dataset_stats, best_params, grid_results, cv_metrics,
                holdout_metrics, active_features):
    """Save full retrain report as JSON."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": dataset_stats,
        "best_hyperparams": best_params,
        "grid_search_top5": grid_results[:5],
        "cv_metrics": cv_metrics,
        "holdout_metrics": holdout_metrics,
        "active_features": active_features,
    }
    with open(REPORT_PATH, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  Report saved to {REPORT_PATH}")


# ══════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════

def run_full():
    start = time.time()

    # Step 1: Build dataset
    dataset, dataset_stats = build_dataset()

    # Step 2: Feature alignment
    X, y = align_features(dataset)
    X, active_features = filter_leaky_features(X, y)

    # Stratified 80/20 split
    print("\n  Stratified 80/20 split (seed=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"  Train: {len(X_train)} ({int((y_train == 0).sum())} clean, "
          f"{int((y_train == 1).sum())} malicious)")
    print(f"  Test:  {len(X_test)} ({int((y_test == 0).sum())} clean, "
          f"{int((y_test == 1).sum())} malicious)")

    scale_pos_weight = float((y_train == 0).sum()) / max(float((y_train == 1).sum()), 1)
    print(f"  scale_pos_weight: {scale_pos_weight:.2f}")

    # Step 3: Grid search
    best_params, grid_results = grid_search(
        X_train, y_train, active_features, scale_pos_weight)

    # Step 4: Train final model
    model = train_final(X_train, y_train, active_features, best_params, scale_pos_weight)

    # Step 5: Threshold optimization
    threshold, cv_metrics = optimize_threshold(
        model, X_train, y_train, active_features,
        best_params=best_params, scale_pos_weight=scale_pos_weight)

    # Step 6: Holdout evaluation
    holdout_metrics, probs = evaluate_holdout(
        model, X_test, y_test, active_features, threshold)

    # Step 7: Export
    export_model_js(model, active_features, threshold,
                    cv_metrics, holdout_metrics, MODEL_OUTPUT)

    preds = (probs >= threshold).astype(int)
    save_confusion_matrix_png(y_test, preds, CONFUSION_MATRIX_PATH)
    save_report(dataset_stats, best_params, grid_results,
                cv_metrics, holdout_metrics, active_features)

    elapsed = time.time() - start
    print("\n" + "=" * 70)
    print(f"RETRAIN COMPLETE ({elapsed:.0f}s)")
    print("=" * 70)
    print(f"  Dataset:   {len(dataset)} samples")
    print(f"  Features:  {len(active_features)}")
    print(f"  Best:      depth={best_params['max_depth']} "
          f"est={best_params['n_estimators']} lr={best_params['learning_rate']}")
    print(f"  Threshold: {threshold:.3f}")
    print(f"  Holdout:   P={holdout_metrics['precision']:.3f} "
          f"R={holdout_metrics['recall']:.3f} F1={holdout_metrics['f1']:.3f} "
          f"AUC={holdout_metrics['auc_roc']:.3f}")
    print(f"  Model:     {MODEL_OUTPUT}")
    print(f"  Report:    {REPORT_PATH}")


def main():
    parser = argparse.ArgumentParser(description="MUAD'DIB ML Retrain")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--full', action='store_true', help='Run all steps')
    group.add_argument('--build-dataset', action='store_true', help='Step 1 only')
    group.add_argument('--train-only', action='store_true',
                       help='Train from cached dataset')
    parser.add_argument('--data-dir', help='Override MUADDIB_DATA path')
    args = parser.parse_args()

    if args.data_dir:
        global MUADDIB_DATA, MUADDIB_ALERTS
        MUADDIB_DATA = Path(args.data_dir)
        MUADDIB_ALERTS = MUADDIB_DATA.parent / "logs" / "alerts"

    if args.full:
        run_full()
    elif args.build_dataset:
        build_dataset()
    elif args.train_only:
        if not DATASET_CACHE.is_file():
            print(f"ERROR: Cached dataset not found at {DATASET_CACHE}", file=sys.stderr)
            print("Run --build-dataset or --full first", file=sys.stderr)
            sys.exit(1)
        records, _ = load_jsonl(DATASET_CACHE)
        # Fake stats for report
        run_full()


if __name__ == '__main__':
    main()
