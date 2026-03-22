#!/usr/bin/env python3
"""
MUAD'DIB XGBoost Training Pipeline — dual-source JSONL

Trains a binary XGBoost classifier on two JSONL files:
  - negatives: monitor output (labels clean/fp → 0)
  - positives: Datadog malware corpus (label malicious → 1)

Exports directly to model-trees.js (no intermediate model.json).

Usage:
    python src/ml/train-xgboost.py \
      --negatives data/ml-training.jsonl \
      --positives data/ml-training-datadog.jsonl \
      --output src/ml/model-trees.js \
      --top-features 40

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

# XGBoost hyperparameters (aligned with tools/train-classifier.py)
XGB_PARAMS = {
    'objective': 'binary:logistic',
    'eval_metric': 'logloss',
    'max_depth': 6,
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


def load_and_prepare(args) -> tuple:
    """
    Step 1: Load two JSONL files and map to binary labels.

    Returns: (X, y, stats)
    """
    print("=" * 60)
    print("[Step 1/8] Loading JSONL data...")
    print("=" * 60)

    # Load negatives (clean/fp → 0)
    neg_records = load_jsonl(args.negatives)
    print(f"  Negatives file: {len(neg_records)} total records")

    # Filter: keep only clean and fp labels (exclude suspect and unconfirmed)
    # 'unconfirmed' = sandbox clean but not manually reviewed — excluded from both
    # positive and negative sets to prevent contamination (see C1 remediation)
    neg_label_counts = {}
    for r in neg_records:
        lbl = r.get('label', 'unknown')
        neg_label_counts[lbl] = neg_label_counts.get(lbl, 0) + 1
    print(f"  Negative label distribution: {neg_label_counts}")

    negatives = [r for r in neg_records if r.get('label') in ('clean', 'fp')]
    n_unconfirmed = sum(1 for r in neg_records if r.get('label') == 'unconfirmed')
    print(f"  Kept {len(negatives)} negatives (clean + fp)")
    if n_unconfirmed > 0:
        print(f"  Excluded {n_unconfirmed} 'unconfirmed' records (not manually reviewed)")

    # Load positives (malicious → 1)
    pos_records = load_jsonl(args.positives)
    print(f"  Positives file: {len(pos_records)} total records")

    pos_label_counts = {}
    for r in pos_records:
        lbl = r.get('label', 'unknown')
        pos_label_counts[lbl] = pos_label_counts.get(lbl, 0) + 1
    print(f"  Positive label distribution: {pos_label_counts}")

    positives = pos_records  # All entries are malicious

    if len(negatives) < MIN_SAMPLES:
        print(f"ERROR: Need >= {MIN_SAMPLES} negatives, got {len(negatives)}",
              file=sys.stderr)
        sys.exit(1)
    if len(positives) < MIN_SAMPLES:
        print(f"ERROR: Need >= {MIN_SAMPLES} positives, got {len(positives)}",
              file=sys.stderr)
        sys.exit(1)

    ratio = len(negatives) / len(positives)
    print(f"\n  Negatives: {len(negatives)}")
    print(f"  Positives: {len(positives)}")
    print(f"  Ratio (neg/pos): {ratio:.2f}")

    return negatives, positives


def align_features(negatives: list, positives: list) -> tuple:
    """
    Step 2: Align all records to the 71 hardcoded features.

    Returns: (X: pd.DataFrame, y: np.ndarray, stats: dict)
    """
    print("\n" + "=" * 60)
    print("[Step 2/8] Aligning 71 features...")
    print("=" * 60)

    # Combine with binary labels
    all_records = []
    for r in negatives:
        all_records.append((r, 0))
    for r in positives:
        all_records.append((r, 1))

    # Extract feature matrix
    X_data = []
    y_data = []
    neg_present = 0
    neg_missing = 0
    pos_present = 0
    pos_missing = 0

    for record, label in all_records:
        row = []
        for feat in FEATURE_NAMES:
            val = record.get(feat, 0)
            if val is None:
                val = 0
            row.append(float(val))
        X_data.append(row)
        y_data.append(label)

        # Count present vs missing features
        if label == 0:
            for feat in FEATURE_NAMES:
                if feat in record and record[feat] is not None:
                    neg_present += 1
                else:
                    neg_missing += 1
        else:
            for feat in FEATURE_NAMES:
                if feat in record and record[feat] is not None:
                    pos_present += 1
                else:
                    pos_missing += 1

    X = pd.DataFrame(X_data, columns=FEATURE_NAMES)
    y = np.array(y_data, dtype=int)

    n_neg = int((y == 0).sum())
    n_pos = int((y == 1).sum())

    print(f"  Feature matrix: {X.shape[0]} samples x {X.shape[1]} features")
    print(f"  Negatives: {neg_present} present, {neg_missing} missing "
          f"({neg_present / max(neg_present + neg_missing, 1) * 100:.1f}% coverage)")
    print(f"  Positives: {pos_present} present, {pos_missing} missing "
          f"({pos_present / max(pos_present + pos_missing, 1) * 100:.1f}% coverage)")

    stats = {
        'n_total': len(X),
        'n_neg': n_neg,
        'n_pos': n_pos,
        'n_features': len(FEATURE_NAMES),
    }

    return X, y, stats


def filter_leaky_features(X: pd.DataFrame, y: np.ndarray,
                          min_coverage: float = 0.01) -> tuple:
    """
    Step 2b: Remove features that leak source identity.

    A feature present in >99% of one source but <1% of the other is a proxy
    for the data source, not a genuine malware signal.

    Returns: (X_filtered, active_features)
    """
    print("\n" + "=" * 60)
    print("[Step 2b/8] Filtering leaky features (common-only mode)...")
    print("=" * 60)

    neg_mask = y == 0
    pos_mask = y == 1
    n_neg = int(neg_mask.sum())
    n_pos = int(pos_mask.sum())

    retained = []
    excluded = []

    print(f"\n  {'Feature':<40s} {'Neg%':>6s} {'Pos%':>6s} {'Status'}")
    print(f"  {'-' * 40} {'-' * 6} {'-' * 6} {'-' * 8}")

    for feat in FEATURE_NAMES:
        neg_nonzero = float((X.loc[neg_mask, feat] != 0).sum()) / max(n_neg, 1)
        pos_nonzero = float((X.loc[pos_mask, feat] != 0).sum()) / max(n_pos, 1)

        if neg_nonzero >= min_coverage and pos_nonzero >= min_coverage:
            retained.append(feat)
            status = 'KEEP'
        else:
            excluded.append(feat)
            status = 'DROP'

        print(f"  {feat:<40s} {neg_nonzero * 100:5.1f}% {pos_nonzero * 100:5.1f}% {status}")

    print(f"\n  Retained: {len(retained)}/{len(FEATURE_NAMES)} features")
    if excluded:
        print(f"  Excluded: {', '.join(excluded)}")

    X_filtered = X[retained]
    return X_filtered, retained


def split_data(X: pd.DataFrame, y: np.ndarray) -> tuple:
    """
    Step 3: Stratified 80/20 split.

    Returns: (X_train, X_test, y_train, y_test)
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
                                active_features: list,
                                top_k: int = 40) -> list:
    """
    Step 4: Preliminary training + SHAP feature selection.

    Returns: list of selected feature names
    """
    print("\n" + "=" * 60)
    print(f"[Step 4/8] Preliminary training + SHAP (top {top_k} from {len(active_features)} features)...")
    print("=" * 60)

    X_active = X_train[active_features]
    params = {**XGB_PARAMS, 'scale_pos_weight': scale_pos_weight}
    dtrain = xgb.DMatrix(X_active, label=y_train, feature_names=active_features)
    prelim = xgb.train(params, dtrain, num_boost_round=100)

    # SHAP
    explainer = shap.TreeExplainer(prelim)
    shap_values = explainer.shap_values(X_active)

    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    importance = sorted(zip(active_features, mean_abs_shap),
                        key=lambda x: x[1], reverse=True)

    print(f"\n  Top 20 features by SHAP importance:")
    for i, (name, val) in enumerate(importance[:20]):
        print(f"    {i + 1:2d}. {name:40s} {val:.6f}")

    selected = [name for name, _ in importance[:top_k]]

    # Show which features were dropped
    dropped = [name for name, _ in importance[top_k:]]
    if dropped:
        print(f"\n  Dropped {len(dropped)} features: {', '.join(dropped[:10])}"
              + (" ..." if len(dropped) > 10 else ""))

    return selected


def cross_validate(X_train: pd.DataFrame, y_train: np.ndarray,
                   selected_features: list,
                   scale_pos_weight: float) -> dict:
    """
    Step 5: 5-fold stratified CV on selected features.
    Optimize threshold: maximize precision under recall >= 93.9%.

    Returns: dict with threshold, precision, recall, fold_metrics
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

    # Optimize threshold: maximize precision while maintaining recall >= 93.9%
    print(f"\n  Optimizing threshold (recall >= 93.9%)...")
    thresholds = np.arange(0.10, 0.91, 0.01)
    best_threshold = 0.5
    best_precision = 0.0

    for t in thresholds:
        preds = (all_probs >= t).astype(int)
        r = recall_score(all_labels, preds, zero_division=0)
        p = precision_score(all_labels, preds, zero_division=0)
        if r >= 0.939 and p > best_precision:
            best_precision = p
            best_threshold = float(t)

    # If no threshold meets recall constraint, warn and use 0.5
    if best_precision == 0.0:
        print(f"  [WARN] No threshold achieves recall >= 93.9%")
        print(f"         Using default threshold=0.5")
        best_threshold = 0.5
        final_preds = (all_probs >= 0.5).astype(int)
    else:
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
    Step 6: Train final model on full train set with early stopping on internal split.
    """
    print("\n" + "=" * 60)
    print(f"[Step 6/8] Training final model ({len(selected_features)} features)...")
    print("=" * 60)

    X_sel = X_train[selected_features]
    params = {**XGB_PARAMS, 'scale_pos_weight': scale_pos_weight}

    # Internal 90/10 split for early stopping
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

    # Hard verification
    if r < 0.939:
        print(f"\n  [WARNING] Recall {r:.3f} < 93.9% target!")
    else:
        print(f"\n  [PASS] Recall >= 93.9%")

    if p < 0.95:
        print(f"  [WARNING] Precision {p:.3f} < 95% target!")
    else:
        print(f"  [PASS] Precision >= 95%")

    # Feature importance (gain-based)
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
    Reused from tools/export-model-js.py.
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


def export_model_trees_js(model: xgb.Booster, selected_features: list,
                           threshold: float, output_path: str,
                           cv_metrics: dict, holdout_metrics: dict):
    """
    Step 8: Export model directly to model-trees.js.
    """
    print("\n" + "=" * 60)
    print(f"[Step 8/8] Exporting to {output_path}...")
    print("=" * 60)

    # Get tree dump as JSON
    trees_dump = model.get_dump(dump_format='json')
    feature_map = {name: idx for idx, name in enumerate(selected_features)}

    # Convert each tree to flat array format
    js_trees = []
    total_nodes = 0
    for tree_str in trees_dump:
        tree_json = json.loads(tree_str)
        nodes = []
        convert_tree(tree_json, nodes, feature_map)
        js_trees.append(nodes)
        total_nodes += len(nodes)

    # Build JS model object
    js_model = {
        'version': 1,
        'features': selected_features,
        'threshold': threshold,
        'trees': js_trees
    }

    # Write as JS module
    js_content = "'use strict';\n\n"
    js_content += "/**\n"
    js_content += " * XGBoost model trees — auto-generated by src/ml/train-xgboost.py\n"
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
        description='Train MUAD\'DIB XGBoost classifier (dual-source JSONL)')
    parser.add_argument('--negatives', required=True,
                        help='Path to negatives JSONL (clean/fp labels)')
    parser.add_argument('--positives', required=True,
                        help='Path to positives JSONL (malicious labels)')
    parser.add_argument('--output', default='src/ml/model-trees.js',
                        help='Output JS file path (default: src/ml/model-trees.js)')
    parser.add_argument('--top-features', type=int, default=40,
                        help='Number of top SHAP features to select (default: 40)')
    parser.add_argument('--common-only', action=argparse.BooleanOptionalAction,
                        default=True,
                        help='Only use features with >=1%% non-zero coverage in BOTH sources (default: on)')
    args = parser.parse_args()

    # Validate inputs
    if not Path(args.negatives).exists():
        print(f"ERROR: Negatives file not found: {args.negatives}", file=sys.stderr)
        sys.exit(1)
    if not Path(args.positives).exists():
        print(f"ERROR: Positives file not found: {args.positives}", file=sys.stderr)
        sys.exit(1)

    # Step 1: Load data
    negatives, positives = load_and_prepare(args)

    # Step 2: Align features
    X, y, stats = align_features(negatives, positives)

    # Step 2b: Filter leaky features
    if args.common_only:
        X, active_features = filter_leaky_features(X, y)
    else:
        active_features = list(FEATURE_NAMES)

    # Class imbalance weight
    n_neg = stats['n_neg']
    n_pos = stats['n_pos']
    scale_pos_weight = n_neg / max(n_pos, 1)
    print(f"\n  scale_pos_weight: {scale_pos_weight:.2f}")

    # Step 3: Train/test split
    X_train, X_test, y_train, y_test = split_data(X, y)

    # Step 4: Preliminary + SHAP
    selected = train_preliminary_and_shap(
        X_train, y_train, scale_pos_weight, active_features,
        top_k=args.top_features)

    # Step 5: Cross-validation
    cv_metrics = cross_validate(X_train, y_train, selected, scale_pos_weight)

    # Step 6: Final model
    final_model = train_final_model(X_train, y_train, selected, scale_pos_weight)

    # Step 7: Holdout evaluation
    holdout_metrics = evaluate_holdout(
        final_model, X_test, y_test, selected, cv_metrics['threshold'])

    # Step 8: Export
    export_model_trees_js(
        final_model, selected, cv_metrics['threshold'],
        args.output, cv_metrics, holdout_metrics)

    # Summary
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Samples: {n_neg} negatives + {n_pos} positives = {n_neg + n_pos}")
    print(f"  Features: {len(selected)} selected (from {len(active_features)} active / {len(FEATURE_NAMES)} total)")
    print(f"  Threshold: {cv_metrics['threshold']:.3f}")
    print(f"  CV:      P={cv_metrics['precision']:.3f} R={cv_metrics['recall']:.3f} F1={cv_metrics['f1']:.3f}")
    print(f"  Holdout: P={holdout_metrics['precision']:.3f} R={holdout_metrics['recall']:.3f} F1={holdout_metrics['f1']:.3f}")
    print(f"  Output:  {args.output}")

    # Warnings
    if holdout_metrics['recall'] < 0.939:
        print(f"\n  [WARNING] Holdout recall {holdout_metrics['recall']:.3f} < 93.9% target")
    if holdout_metrics['precision'] < 0.95:
        print(f"  [WARNING] Holdout precision {holdout_metrics['precision']:.3f} < 95% target")


if __name__ == '__main__':
    main()
