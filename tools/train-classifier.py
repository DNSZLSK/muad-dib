#!/usr/bin/env python3
"""
MUAD'DIB ML Classifier Training Pipeline

Trains a binary XGBoost classifier to distinguish true positives from false
positives in the T1 zone (score 20-34). Designed to be run offline — no
Python dependency in production.

Usage:
    python tools/train-classifier.py [--data data/ml-training.jsonl] [--output model.json]

Label strategy:
    - Positives: Datadog ground-truth malware corpus (scanned with muaddib)
    - Negatives: monitor label='clean' packages (0 findings = truly benign)
    - EXCLUDED: 'suspect' (unverified), 'fp' (auto-labeled, biased)

Output:
    - model.json: XGBoost tree dump + feature list + threshold
    - Use tools/export-model-js.py to convert to src/ml/model-trees.js
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import shap
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import xgboost as xgb


# --- Constants ---

# Feature columns to EXCLUDE (identity/metadata, not features)
IDENTITY_COLS = {'name', 'version', 'ecosystem', 'timestamp', 'label', 'tier'}

# Minimum samples required for training
MIN_SAMPLES = 100

# XGBoost hyperparameters (tuned for supply-chain threat detection)
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


def load_jsonl(filepath: str) -> pd.DataFrame:
    """Load JSONL file into DataFrame."""
    records = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"  [WARN] Skipping malformed line {line_num}", file=sys.stderr)
    return pd.DataFrame(records)


def prepare_data(df: pd.DataFrame) -> tuple:
    """
    Prepare training data from monitor JSONL.

    Returns: (X, y, feature_names, stats_dict)
    """
    print(f"\n[1/5] Loading data: {len(df)} total records")

    # Show label distribution
    label_counts = df['label'].value_counts()
    print(f"  Label distribution:")
    for label, count in label_counts.items():
        print(f"    {label}: {count}")

    # Filter to usable labels only
    # Positives: 'confirmed' (manually verified malicious)
    # Negatives: 'clean' (0 findings, truly benign)
    # Excluded: 'suspect' (unverified), 'fp' (auto-labeled bias)
    positives = df[df['label'] == 'confirmed'].copy()
    negatives = df[df['label'] == 'clean'].copy()

    # For negatives in T1 zone training: filter to score 20-34
    # This focuses the model on the decision boundary
    negatives_t1 = negatives[(negatives['score'] >= 20) & (negatives['score'] < 35)]

    print(f"\n  Training set:")
    print(f"    Positives (confirmed): {len(positives)}")
    print(f"    Negatives (clean): {len(negatives)} total, {len(negatives_t1)} in T1 zone")

    # If not enough T1 negatives, use all clean negatives
    if len(negatives_t1) < 50:
        print(f"    [INFO] Not enough T1 negatives ({len(negatives_t1)}), using all clean samples")
        neg_sample = negatives
    else:
        neg_sample = negatives_t1

    # Combine
    combined = pd.concat([positives, neg_sample], ignore_index=True)
    combined['_target'] = (combined['label'] == 'confirmed').astype(int)

    # Extract feature columns
    feature_cols = [col for col in combined.columns
                    if col not in IDENTITY_COLS and col != '_target'
                    and not col.startswith('_')]
    feature_cols = sorted(feature_cols)

    X = combined[feature_cols].fillna(0).astype(float)
    y = combined['_target']

    stats = {
        'total_records': len(df),
        'positives': len(positives),
        'negatives_total': len(negatives),
        'negatives_t1': len(negatives_t1),
        'negatives_used': len(neg_sample),
        'features': len(feature_cols),
        'class_balance': f"{len(positives)}:{len(neg_sample)}"
    }

    return X, y, feature_cols, stats


def select_features_shap(model, X: pd.DataFrame, feature_names: list,
                          top_k: int = 40) -> list:
    """
    Use SHAP to select top-k most important features.
    """
    print(f"\n[3/5] SHAP feature selection (top {top_k})...")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)

    # Mean absolute SHAP value per feature
    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    importance = sorted(zip(feature_names, mean_abs_shap),
                        key=lambda x: x[1], reverse=True)

    print(f"\n  Top 20 features by SHAP importance:")
    for i, (name, val) in enumerate(importance[:20]):
        print(f"    {i + 1:2d}. {name:40s} {val:.4f}")

    selected = [name for name, _ in importance[:top_k]]
    return selected


def cross_validate(X: pd.DataFrame, y: pd.Series, feature_names: list,
                   scale_pos_weight: float) -> dict:
    """
    5-fold stratified CV with precision@recall>=93.9% optimization.
    """
    print(f"\n[4/5] 5-fold stratified cross-validation...")

    params = {**XGB_PARAMS, 'scale_pos_weight': scale_pos_weight}
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)

    fold_metrics = []
    all_probs = np.zeros(len(y))
    all_labels = np.zeros(len(y))

    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
        X_train, X_val = X.iloc[train_idx], X.iloc[val_idx]
        y_train, y_val = y.iloc[train_idx], y.iloc[val_idx]

        dtrain = xgb.DMatrix(X_train, label=y_train, feature_names=feature_names)
        dval = xgb.DMatrix(X_val, label=y_val, feature_names=feature_names)

        model = xgb.train(
            params, dtrain, num_boost_round=N_ESTIMATORS,
            evals=[(dval, 'val')], verbose_eval=False,
            early_stopping_rounds=20
        )

        probs = model.predict(dval)
        all_probs[val_idx] = probs
        all_labels[val_idx] = y_val.values

        # Default threshold 0.5
        preds = (probs >= 0.5).astype(int)
        p = precision_score(y_val, preds, zero_division=0)
        r = recall_score(y_val, preds, zero_division=0)
        f1 = f1_score(y_val, preds, zero_division=0)
        fold_metrics.append({'precision': p, 'recall': r, 'f1': f1})
        print(f"  Fold {fold + 1}: P={p:.3f} R={r:.3f} F1={f1:.3f}")

    # Find optimal threshold: maximize precision while maintaining recall >= 93.9%
    thresholds = np.arange(0.1, 0.9, 0.01)
    best_threshold = 0.5
    best_precision = 0

    for t in thresholds:
        preds = (all_probs >= t).astype(int)
        r = recall_score(all_labels, preds, zero_division=0)
        p = precision_score(all_labels, preds, zero_division=0)
        if r >= 0.939 and p > best_precision:
            best_precision = p
            best_threshold = t

    final_preds = (all_probs >= best_threshold).astype(int)
    final_p = precision_score(all_labels, final_preds, zero_division=0)
    final_r = recall_score(all_labels, final_preds, zero_division=0)
    cm = confusion_matrix(all_labels, final_preds)

    print(f"\n  Optimal threshold: {best_threshold:.2f}")
    print(f"  Final metrics: P={final_p:.3f} R={final_r:.3f}")
    print(f"  Confusion matrix:\n    {cm}")

    return {
        'threshold': round(float(best_threshold), 3),
        'precision': round(float(final_p), 4),
        'recall': round(float(final_r), 4),
        'fold_metrics': fold_metrics,
        'confusion_matrix': cm.tolist()
    }


def train_final_model(X: pd.DataFrame, y: pd.Series, feature_names: list,
                       scale_pos_weight: float) -> xgb.Booster:
    """Train final model on all data."""
    print(f"\n[5/5] Training final model on all data...")
    params = {**XGB_PARAMS, 'scale_pos_weight': scale_pos_weight}
    dtrain = xgb.DMatrix(X, label=y, feature_names=feature_names)
    model = xgb.train(params, dtrain, num_boost_round=N_ESTIMATORS)
    return model


def export_model_json(model: xgb.Booster, feature_names: list,
                       threshold: float, output_path: str, cv_metrics: dict):
    """Export model as JSON tree dump."""
    trees_dump = model.get_dump(dump_format='json')

    model_data = {
        'version': 1,
        'algorithm': 'xgboost',
        'features': feature_names,
        'threshold': threshold,
        'n_trees': len(trees_dump),
        'cv_metrics': {
            'precision': cv_metrics['precision'],
            'recall': cv_metrics['recall'],
            'threshold': cv_metrics['threshold']
        },
        'trees_raw': [json.loads(t) for t in trees_dump]
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(model_data, f, indent=2)

    size_mb = Path(output_path).stat().st_size / (1024 * 1024)
    print(f"\n  Model exported to {output_path} ({size_mb:.1f} MB)")
    print(f"  {len(trees_dump)} trees, {len(feature_names)} features, threshold={threshold:.3f}")


def main():
    parser = argparse.ArgumentParser(description='Train MUAD\'DIB ML classifier')
    parser.add_argument('--data', default='data/ml-training.jsonl',
                        help='Path to JSONL training data')
    parser.add_argument('--output', default='model.json',
                        help='Path for model JSON output')
    parser.add_argument('--top-features', type=int, default=40,
                        help='Number of top SHAP features to select')
    args = parser.parse_args()

    # Load data
    if not Path(args.data).exists():
        print(f"ERROR: Training data not found: {args.data}", file=sys.stderr)
        sys.exit(1)

    df = load_jsonl(args.data)
    if len(df) < MIN_SAMPLES:
        print(f"ERROR: Need at least {MIN_SAMPLES} samples, got {len(df)}", file=sys.stderr)
        sys.exit(1)

    # Prepare data
    X, y, feature_names, stats = prepare_data(df)
    print(f"\n[2/5] Training with {stats['features']} features, "
          f"balance {stats['class_balance']}")

    # Class imbalance weight
    n_pos = y.sum()
    n_neg = len(y) - n_pos
    scale_pos_weight = n_neg / max(n_pos, 1)
    print(f"  scale_pos_weight: {scale_pos_weight:.2f}")

    # Phase 1: Train preliminary model for SHAP feature selection
    prelim_params = {**XGB_PARAMS, 'scale_pos_weight': scale_pos_weight}
    dtrain = xgb.DMatrix(X, label=y, feature_names=feature_names)
    prelim_model = xgb.train(prelim_params, dtrain, num_boost_round=100)

    # SHAP feature selection
    selected_features = select_features_shap(
        prelim_model, X, feature_names, top_k=args.top_features)

    # Retrain with selected features
    X_selected = X[selected_features]

    # Cross-validate
    cv_metrics = cross_validate(X_selected, y, selected_features, scale_pos_weight)

    # Train final model
    final_model = train_final_model(X_selected, y, selected_features, scale_pos_weight)

    # Export
    export_model_json(final_model, selected_features, cv_metrics['threshold'],
                       args.output, cv_metrics)

    print(f"\n{'=' * 60}")
    print(f"Training complete!")
    print(f"  Samples: {stats['positives']} malicious + {stats['negatives_used']} clean")
    print(f"  Features: {len(selected_features)} (from {stats['features']} total)")
    print(f"  Precision: {cv_metrics['precision']:.1%}")
    print(f"  Recall: {cv_metrics['recall']:.1%}")
    print(f"  Threshold: {cv_metrics['threshold']:.3f}")
    print(f"\nNext: python tools/export-model-js.py {args.output}")


if __name__ == '__main__':
    main()
