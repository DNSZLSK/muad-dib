#!/usr/bin/env python3
"""
MUAD'DIB Bundler Detector Training Pipeline — single-source JSONL (ML2)

Trains a binary XGBoost classifier to distinguish bundler false positives
from true malicious packages in the high-score zone (score >= 35).

Unlike ML1 (train-xgboost.py) which uses dual sources (monitor + Datadog),
this model uses a SINGLE source (monitor JSONL) for both classes:
  - Class 0 (clean/bundler FP): label 'fp' AND score >= 35
  - Class 1 (malicious):        HC threat types present AND score >= 35

This avoids cross-source leakage entirely — both classes share the same
feature distribution from the monitor pipeline.

Features excluded at training time (always 0 at inference due to guard rails):
  - type_reverse_shell, type_binary_dropper, type_staged_binary_payload
  - has_typosquat, has_ioc_match

Exports directly to model-bundler.js.

Usage:
    python src/ml/train-bundler-detector.py \\
      --input data/ml-training.jsonl \\
      --output src/ml/model-bundler.js \\
      --top-features 30

    # Optional: add Datadog positives for class 1 augmentation
    python src/ml/train-bundler-detector.py \\
      --input data/ml-training.jsonl \\
      --positives-extra data/ml-training-datadog-full.jsonl \\
      --output src/ml/model-bundler.js

Dependencies: see tools/requirements-ml.txt
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import shap
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import (
    precision_score, recall_score, f1_score, confusion_matrix
)
import xgboost as xgb


# --- Constants ---

# Identity columns to exclude from features
IDENTITY_COLS = {'name', 'version', 'ecosystem', 'timestamp', 'label', 'tier'}

# Minimum samples per class
MIN_SAMPLES = 50

# Score threshold for the bundler detector zone
SCORE_THRESHOLD = 35

# HC threat types used to construct the positive class (all in TOP_THREAT_TYPES)
BUNDLER_HC_TYPES = [
    'type_intent_credential_exfil',
    'type_intent_command_exfil',
    'type_lifecycle_shell_pipe',
    'type_reverse_shell',
    'type_cross_file_dataflow',
]

# Features to EXCLUDE from training — always 0 at inference because the
# classifier's guard rail 2a intercepts these types before the bundler model
INFERENCE_EXCLUDED_FEATURES = {
    'type_reverse_shell',           # in HC_TYPES → intercepted by guard rail
    'type_binary_dropper',          # in HC_TYPES → intercepted by guard rail
    'type_staged_binary_payload',   # in HC_TYPES → intercepted by guard rail
    'has_typosquat',                # typosquat_detected in HC_TYPES
    'has_ioc_match',                # known_malicious_* in HC_TYPES
}

# XGBoost hyperparameters (same base as ML1)
XGB_PARAMS = {
    'objective': 'binary:logistic',
    'eval_metric': 'logloss',
    'max_depth': 5,          # slightly shallower than ML1 (smaller dataset expected)
    'learning_rate': 0.1,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'min_child_weight': 5,
    'gamma': 0.1,
    'reg_alpha': 0.1,
    'reg_lambda': 1.0,
    'seed': 42,
    'verbosity': 0,
}

N_ESTIMATORS = 200
N_FOLDS = 5

# Hardcoded 71 features — exact copy of feature-extractor.js output keys
FEATURE_NAMES = [
    # Scoring (4)
    'score', 'max_file_score', 'package_score', 'global_risk_score',
    # Severity counts (5)
    'count_total', 'count_critical', 'count_high', 'count_medium', 'count_low',
    # Distinct types (1)
    'distinct_threat_types',
    # Per-type counts (31 TOP_THREAT_TYPES + 1 other = 32)
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
    'type_mcp_config_injection', 'type_other',
    # Boolean behavioral signals (10)
    'has_lifecycle_script', 'has_network_access', 'has_obfuscation',
    'has_env_access', 'has_eval', 'has_staged_payload', 'has_typosquat',
    'has_ioc_match', 'has_intent_pair', 'has_sandbox_finding',
    # File distribution (3)
    'file_count_with_threats', 'file_score_mean', 'file_score_max',
    # Severity concentration (3)
    'severity_ratio_high', 'max_single_points', 'points_concentration',
    # Package metadata (3)
    'unpacked_size_bytes', 'dep_count', 'dev_dep_count',
    # Reputation (1)
    'reputation_factor',
    # Enriched registry metadata (9) — Phase 2a
    'package_age_days', 'weekly_downloads', 'version_count',
    'author_package_count', 'has_repository', 'readme_size',
    'file_count_total', 'has_tests', 'threat_density',
]

assert len(FEATURE_NAMES) == 71, f"Expected 71 features, got {len(FEATURE_NAMES)}"

# Features available for training (after excluding inference-blocked features)
TRAINABLE_FEATURES = [f for f in FEATURE_NAMES if f not in INFERENCE_EXCLUDED_FEATURES]


# --- Data loading ---

def load_jsonl(filepath: str) -> list:
    """Load JSONL file into list of dicts."""
    records = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"  [WARN] Skipping malformed line {line_num} in {filepath}",
                      file=sys.stderr)
    return records


def has_hc_type(record: dict) -> bool:
    """Check if a record has any HC threat type with non-zero count."""
    for hc_type in BUNDLER_HC_TYPES:
        if record.get(hc_type, 0) > 0:
            return True
    return False


def load_and_prepare(args) -> tuple:
    """
    Step 1: Load monitor JSONL and split into bundler classes.

    Class 0 (bundler FP): label == 'fp' AND score >= score_threshold
    Class 1 (malicious):  HC type present AND score >= score_threshold

    Returns: (negatives, positives)
    """
    score_threshold = args.score_threshold

    print("=" * 60)
    print("[Step 1/8] Loading JSONL data...")
    print("=" * 60)

    records = load_jsonl(args.input)
    print(f"  Input file: {len(records)} total records")

    # Count label distribution
    label_counts = {}
    for r in records:
        lbl = r.get('label', 'unknown')
        label_counts[lbl] = label_counts.get(lbl, 0) + 1
    print(f"  Label distribution: {label_counts}")

    # Filter to score >= score_threshold
    high_score = [r for r in records if r.get('score', 0) >= score_threshold]
    print(f"  Records with score >= {score_threshold}: {len(high_score)}")

    # Class 0: FP labels with high score (bundler false positives)
    # Exclude 'unconfirmed' — not manually reviewed, may be contaminated (C1 remediation)
    negatives = [r for r in high_score if r.get('label') == 'fp']
    print(f"  Class 0 (bundler FP): {len(negatives)}")

    # Class 1: records with HC types and high score
    # Accept any label (suspect, confirmed, malicious) — the HC type is the signal
    # Exclude 'unconfirmed' and 'fp' from positives
    positives = [r for r in high_score if has_hc_type(r) and r.get('label') not in ('fp', 'unconfirmed')]
    print(f"  Class 1 (HC malicious): {len(positives)}")

    # Optional: augment positives from extra file
    if args.positives_extra and Path(args.positives_extra).exists():
        extra_records = load_jsonl(args.positives_extra)
        extra_high = [r for r in extra_records
                      if r.get('score', 0) >= score_threshold and has_hc_type(r)]
        print(f"  Extra positives from {args.positives_extra}: {len(extra_high)}")
        positives.extend(extra_high)
        print(f"  Class 1 total (with extra): {len(positives)}")

    if len(negatives) < MIN_SAMPLES:
        print(f"\nERROR: Need >= {MIN_SAMPLES} negatives (bundler FPs with score >= {score_threshold}), "
              f"got {len(negatives)}",
              file=sys.stderr)
        print(f"  Try lowering the score threshold with --score-threshold",
              file=sys.stderr)
        sys.exit(1)
    if len(positives) < MIN_SAMPLES:
        print(f"\nERROR: Need >= {MIN_SAMPLES} positives (HC types with score >= {score_threshold}), "
              f"got {len(positives)}",
              file=sys.stderr)
        print(f"  Try: --positives-extra data/ml-training-datadog-full.jsonl",
              file=sys.stderr)
        sys.exit(1)

    ratio = len(negatives) / len(positives)
    print(f"\n  Negatives: {len(negatives)}")
    print(f"  Positives: {len(positives)}")
    print(f"  Ratio (neg/pos): {ratio:.2f}")

    return negatives, positives


def align_features(negatives: list, positives: list) -> tuple:
    """
    Step 2: Align all records to the trainable features (71 - excluded).

    Returns: (X, y, stats)
    """
    print("\n" + "=" * 60)
    print(f"[Step 2/8] Aligning {len(TRAINABLE_FEATURES)} trainable features "
          f"({len(INFERENCE_EXCLUDED_FEATURES)} excluded)...")
    print("=" * 60)

    print(f"  Excluded features: {', '.join(sorted(INFERENCE_EXCLUDED_FEATURES))}")

    all_records = []
    for r in negatives:
        all_records.append((r, 0))
    for r in positives:
        all_records.append((r, 1))

    X_data = []
    y_data = []

    for record, label in all_records:
        row = []
        for feat in TRAINABLE_FEATURES:
            val = record.get(feat, 0)
            if val is None:
                val = 0
            row.append(float(val))
        X_data.append(row)
        y_data.append(label)

    X = pd.DataFrame(X_data, columns=TRAINABLE_FEATURES)
    y = np.array(y_data, dtype=int)

    n_neg = int((y == 0).sum())
    n_pos = int((y == 1).sum())

    print(f"  Feature matrix: {X.shape[0]} samples x {X.shape[1]} features")

    stats = {
        'n_total': len(X),
        'n_neg': n_neg,
        'n_pos': n_pos,
        'n_features': len(TRAINABLE_FEATURES),
    }

    return X, y, stats


def split_data(X: pd.DataFrame, y: np.ndarray) -> tuple:
    """
    Step 3: Stratified 80/20 split.
    """
    print("\n" + "=" * 60)
    print("[Step 3/8] Stratified train/test split (80/20, seed=42)...")
    print("=" * 60)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    print(f"  Train: {len(X_train)} ({int((y_train == 0).sum())} neg, "
          f"{int((y_train == 1).sum())} pos)")
    print(f"  Test:  {len(X_test)} ({int((y_test == 0).sum())} neg, "
          f"{int((y_test == 1).sum())} pos)")

    return X_train, X_test, y_train, y_test


def train_preliminary_and_shap(X_train: pd.DataFrame, y_train: np.ndarray,
                                scale_pos_weight: float,
                                top_k: int = 30) -> list:
    """
    Step 4: Preliminary training + SHAP feature selection.
    """
    print("\n" + "=" * 60)
    print(f"[Step 4/8] Preliminary training + SHAP (top {top_k} from "
          f"{len(TRAINABLE_FEATURES)} features)...")
    print("=" * 60)

    params = {**XGB_PARAMS, 'scale_pos_weight': scale_pos_weight}
    dtrain = xgb.DMatrix(X_train, label=y_train, feature_names=list(X_train.columns))
    prelim = xgb.train(params, dtrain, num_boost_round=100)

    explainer = shap.TreeExplainer(prelim)
    shap_values = explainer.shap_values(X_train)

    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    importance = sorted(zip(X_train.columns, mean_abs_shap),
                        key=lambda x: x[1], reverse=True)

    print(f"\n  Top 20 features by SHAP importance:")
    for i, (name, val) in enumerate(importance[:20]):
        print(f"    {i + 1:2d}. {name:40s} {val:.6f}")

    # Cap to available features if fewer than top_k
    effective_k = min(top_k, len(importance))
    selected = [name for name, _ in importance[:effective_k]]

    dropped = [name for name, _ in importance[effective_k:]]
    if dropped:
        print(f"\n  Dropped {len(dropped)} features: {', '.join(dropped[:10])}"
              + (" ..." if len(dropped) > 10 else ""))

    return selected


def cross_validate(X_train: pd.DataFrame, y_train: np.ndarray,
                   selected_features: list,
                   scale_pos_weight: float) -> dict:
    """
    Step 5: 5-fold stratified CV on selected features.
    For the bundler model, we optimize precision (minimize FN on malicious)
    while maintaining reasonable recall.
    """
    print("\n" + "=" * 60)
    print(f"[Step 5/8] 5-fold stratified CV ({len(selected_features)} features)...")
    print("=" * 60)

    X_sel = X_train[selected_features]
    params = {**XGB_PARAMS, 'scale_pos_weight': scale_pos_weight}
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)

    fold_metrics = []
    all_probs = np.zeros(len(y_train))
    all_labels = np.zeros(len(y_train))

    for fold, (train_idx, val_idx) in enumerate(skf.split(X_sel, y_train)):
        X_tr = X_sel.iloc[train_idx]
        X_va = X_sel.iloc[val_idx]
        y_tr = y_train[train_idx]
        y_va = y_train[val_idx]

        dtrain = xgb.DMatrix(X_tr, label=y_tr, feature_names=selected_features)
        dval = xgb.DMatrix(X_va, label=y_va, feature_names=selected_features)

        model = xgb.train(
            params, dtrain, num_boost_round=N_ESTIMATORS,
            evals=[(dval, 'val')], verbose_eval=False,
            early_stopping_rounds=20
        )

        probs = model.predict(dval)
        all_probs[val_idx] = probs
        all_labels[val_idx] = y_va

        preds = (probs >= 0.5).astype(int)
        p = precision_score(y_va, preds, zero_division=0)
        r = recall_score(y_va, preds, zero_division=0)
        f1 = f1_score(y_va, preds, zero_division=0)
        fold_metrics.append({'precision': p, 'recall': r, 'f1': f1})
        print(f"  Fold {fold + 1}: P={p:.3f} R={r:.3f} F1={f1:.3f}")

    # Optimize threshold: maximize F1 (balanced precision/recall)
    # For bundler detector, false negatives (missing real malware) are worse
    # than false positives (flagging a bundler as malicious)
    print(f"\n  Optimizing threshold (maximize recall on malicious, precision >= 80%)...")
    thresholds = np.arange(0.10, 0.91, 0.01)
    best_threshold = 0.5
    best_recall = 0.0

    for t in thresholds:
        preds = (all_probs >= t).astype(int)
        r = recall_score(all_labels, preds, zero_division=0)
        p = precision_score(all_labels, preds, zero_division=0)
        if p >= 0.80 and r > best_recall:
            best_recall = r
            best_threshold = float(t)

    if best_recall == 0.0:
        print(f"  [WARN] No threshold achieves precision >= 80%")
        print(f"         Using default threshold=0.5")
        best_threshold = 0.5

    final_preds = (all_probs >= best_threshold).astype(int)
    final_p = precision_score(all_labels, final_preds, zero_division=0)
    final_r = recall_score(all_labels, final_preds, zero_division=0)
    final_f1 = f1_score(all_labels, final_preds, zero_division=0)
    cm = confusion_matrix(all_labels, final_preds)

    print(f"\n  Optimal threshold: {best_threshold:.2f}")
    print(f"  CV metrics: P={final_p:.3f} R={final_r:.3f} F1={final_f1:.3f}")
    print(f"  Confusion matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")

    return {
        'threshold': round(best_threshold, 3),
        'precision': round(float(final_p), 4),
        'recall': round(float(final_r), 4),
        'f1': round(float(final_f1), 4),
        'fold_metrics': fold_metrics,
        'confusion_matrix': cm.tolist()
    }


def train_final_model(X_train: pd.DataFrame, y_train: np.ndarray,
                       selected_features: list,
                       scale_pos_weight: float) -> xgb.Booster:
    """
    Step 6: Train final model on full train set with early stopping.
    """
    print("\n" + "=" * 60)
    print(f"[Step 6/8] Training final model ({len(selected_features)} features)...")
    print("=" * 60)

    X_sel = X_train[selected_features]
    params = {**XGB_PARAMS, 'scale_pos_weight': scale_pos_weight}

    X_tr, X_es, y_tr, y_es = train_test_split(
        X_sel, y_train, test_size=0.1, stratify=y_train, random_state=42
    )

    dtrain = xgb.DMatrix(X_tr, label=y_tr, feature_names=selected_features)
    des = xgb.DMatrix(X_es, label=y_es, feature_names=selected_features)

    model = xgb.train(
        params, dtrain, num_boost_round=N_ESTIMATORS,
        evals=[(des, 'early_stop')], verbose_eval=False,
        early_stopping_rounds=20
    )

    best_round = model.best_iteration if hasattr(model, 'best_iteration') else N_ESTIMATORS
    print(f"  Best iteration: {best_round}")

    return model


def evaluate_holdout(model: xgb.Booster, X_test: pd.DataFrame,
                      y_test: np.ndarray, selected_features: list,
                      threshold: float) -> dict:
    """
    Step 7: Evaluate on holdout test set.
    """
    print("\n" + "=" * 60)
    print(f"[Step 7/8] Holdout evaluation (threshold={threshold:.3f})...")
    print("=" * 60)

    X_sel = X_test[selected_features]
    dtest = xgb.DMatrix(X_sel, label=y_test, feature_names=selected_features)
    probs = model.predict(dtest)

    preds = (probs >= threshold).astype(int)
    p = precision_score(y_test, preds, zero_division=0)
    r = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    cm = confusion_matrix(y_test, preds)

    tn, fp_count, fn, tp = cm.ravel()

    print(f"  Precision: {p:.3f}")
    print(f"  Recall:    {r:.3f}")
    print(f"  F1:        {f1:.3f}")
    print(f"  Confusion matrix:")
    print(f"    TN={tn}  FP={fp_count}")
    print(f"    FN={fn}  TP={tp}")

    # Sanity check: perfect metrics = likely leakage
    if p == 1.0 and r == 1.0:
        print(f"\n  [WARNING] Perfect precision AND recall — possible data leakage!")
    elif f1 > 0.99:
        print(f"\n  [WARNING] F1 > 0.99 — verify no leakage")

    # Feature importance
    importance = model.get_score(importance_type='gain')
    sorted_imp = sorted(importance.items(), key=lambda x: x[1], reverse=True)
    print(f"\n  Top 20 features (gain-based):")
    for i, (name, val) in enumerate(sorted_imp[:20]):
        print(f"    {i + 1:2d}. {name:40s} {val:.4f}")

    return {
        'precision': round(float(p), 4),
        'recall': round(float(r), 4),
        'f1': round(float(f1), 4),
        'confusion_matrix': cm.tolist(),
        'tp': int(tp), 'fp': int(fp_count),
        'fn': int(fn), 'tn': int(tn)
    }


def convert_tree(tree_json: dict, nodes: list, feature_map: dict) -> int:
    """
    Recursively convert an XGBoost tree JSON node to flat array format.
    Same format as model-trees.js.
    """
    idx = len(nodes)
    nodes.append(None)

    if 'leaf' in tree_json:
        nodes[idx] = {
            'f': -1,
            't': 0,
            'y': 0,
            'n': 0,
            'v': round(tree_json['leaf'], 6)
        }
    else:
        split_feature = tree_json.get('split', '')
        feature_idx = feature_map.get(split_feature, -1)
        threshold = tree_json.get('split_condition', 0)

        children = tree_json.get('children', [])
        yes_child = tree_json.get('yes', 0)
        no_child = tree_json.get('no', 0)

        yes_tree = None
        no_tree = None
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

        nodes[idx] = {
            'f': feature_idx,
            't': round(threshold, 6),
            'y': yes_idx,
            'n': no_idx,
            'v': 0
        }

    return idx


def export_model_bundler_js(model: xgb.Booster, selected_features: list,
                             threshold: float, output_path: str,
                             cv_metrics: dict, holdout_metrics: dict):
    """
    Step 8: Export model directly to model-bundler.js.
    """
    print("\n" + "=" * 60)
    print(f"[Step 8/8] Exporting to {output_path}...")
    print("=" * 60)

    trees_dump = model.get_dump(dump_format='json')
    feature_map = {name: idx for idx, name in enumerate(selected_features)}

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
        'features': selected_features,
        'threshold': threshold,
        'trees': js_trees
    }

    js_content = "'use strict';\n\n"
    js_content += "/**\n"
    js_content += " * Bundler detector model trees — auto-generated by src/ml/train-bundler-detector.py\n"
    js_content += f" * {len(js_trees)} trees, {len(selected_features)} features, threshold={threshold}\n"
    js_content += f" * CV: P={cv_metrics['precision']:.3f} R={cv_metrics['recall']:.3f} F1={cv_metrics['f1']:.3f}\n"
    js_content += f" * Holdout: P={holdout_metrics['precision']:.3f} R={holdout_metrics['recall']:.3f} F1={holdout_metrics['f1']:.3f}\n"
    js_content += " * DO NOT EDIT MANUALLY\n"
    js_content += " */\n\n"
    js_content += f"module.exports = {json.dumps(js_model, separators=(',', ':'))};\n"

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(js_content)

    size_kb = Path(output_path).stat().st_size / 1024
    print(f"  Trees: {len(js_trees)}")
    print(f"  Total nodes: {total_nodes}")
    print(f"  Features: {len(selected_features)}")
    print(f"  Threshold: {threshold:.3f}")
    print(f"  File size: {size_kb:.1f} KB")


def main():
    parser = argparse.ArgumentParser(
        description='Train MUAD\'DIB bundler detector model (single-source JSONL)')
    parser.add_argument('--input', required=True,
                        help='Path to monitor JSONL (all labels)')
    parser.add_argument('--positives-extra', default=None,
                        help='Optional extra positives JSONL (Datadog) for class 1 augmentation')
    parser.add_argument('--output', default='src/ml/model-bundler.js',
                        help='Output JS file path (default: src/ml/model-bundler.js)')
    parser.add_argument('--top-features', type=int, default=30,
                        help='Number of top SHAP features to select (default: 30)')
    parser.add_argument('--score-threshold', type=int, default=SCORE_THRESHOLD,
                        help=f'Minimum score for both classes (default: {SCORE_THRESHOLD})')
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Step 1: Load data
    negatives, positives = load_and_prepare(args)

    # Step 2: Align features
    X, y, stats = align_features(negatives, positives)

    # Class imbalance weight
    n_neg = stats['n_neg']
    n_pos = stats['n_pos']
    scale_pos_weight = n_neg / max(n_pos, 1)
    print(f"\n  scale_pos_weight: {scale_pos_weight:.2f}")

    # Step 3: Train/test split
    X_train, X_test, y_train, y_test = split_data(X, y)

    # Step 4: Preliminary + SHAP
    selected = train_preliminary_and_shap(
        X_train, y_train, scale_pos_weight,
        top_k=args.top_features)

    # Step 5: Cross-validation
    cv_metrics = cross_validate(X_train, y_train, selected, scale_pos_weight)

    # Step 6: Final model
    final_model = train_final_model(X_train, y_train, selected, scale_pos_weight)

    # Step 7: Holdout evaluation
    holdout_metrics = evaluate_holdout(
        final_model, X_test, y_test, selected, cv_metrics['threshold'])

    # Step 8: Export
    export_model_bundler_js(
        final_model, selected, cv_metrics['threshold'],
        args.output, cv_metrics, holdout_metrics)

    # Summary
    print("\n" + "=" * 60)
    print("BUNDLER DETECTOR TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Samples: {n_neg} negatives (bundler FP) + {n_pos} positives (HC malicious) = {n_neg + n_pos}")
    print(f"  Features: {len(selected)} selected (from {len(TRAINABLE_FEATURES)} trainable / {len(FEATURE_NAMES)} total)")
    print(f"  Excluded features: {', '.join(sorted(INFERENCE_EXCLUDED_FEATURES))}")
    print(f"  Threshold: {cv_metrics['threshold']:.3f}")
    print(f"  CV:      P={cv_metrics['precision']:.3f} R={cv_metrics['recall']:.3f} F1={cv_metrics['f1']:.3f}")
    print(f"  Holdout: P={holdout_metrics['precision']:.3f} R={holdout_metrics['recall']:.3f} F1={holdout_metrics['f1']:.3f}")
    print(f"  Output:  {args.output}")

    # Warnings
    if holdout_metrics['f1'] > 0.99:
        print(f"\n  [WARNING] F1 > 0.99 — verify no data leakage")
    if holdout_metrics['recall'] < 0.80:
        print(f"\n  [WARNING] Holdout recall {holdout_metrics['recall']:.3f} < 80%")
    if holdout_metrics['precision'] < 0.80:
        print(f"  [WARNING] Holdout precision {holdout_metrics['precision']:.3f} < 80%")


if __name__ == '__main__':
    main()
