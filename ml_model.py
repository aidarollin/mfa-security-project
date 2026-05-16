"""
Random Forest risk classifier — detects suspicious login behaviour.

Features
--------
failed_attempts : prior failed logins for this user (capped at 10)
short_interval  : 1 if this attempt came < 5 s after the previous one
unknown_device  : 1 if device_id is not in the user's known-device list
unusual_hour    : 1 if login hour is between 23:00 and 05:59
password_match  : 1 if the submitted password was correct

Labels
------
0 = low    → standard OTP MFA
1 = medium → OTP MFA + 2 s artificial delay
2 = high   → temporary block (regardless of password correctness)
"""

import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

MODEL_PATH = os.path.join("model", "risk_classifier.pkl")

FEATURE_NAMES = [
    "failed_attempts",
    "short_interval",
    "unknown_device",
    "unusual_hour",
    "password_match",
]

_clf_cache = None


# ── Synthetic training data ────────────────────────────────────────────────────

def _make_dataset():
    rng = np.random.default_rng(42)
    rows, labels = [], []

    def add(n, fa_lo, fa_hi, si, ud, uh, pm, label):
        for _ in range(n):
            fa = int(rng.integers(fa_lo, fa_hi + 1))
            rows.append([fa, si, ud, uh, pm])
            labels.append(label)

    # LOW RISK — legitimate user, known device, correct password, few/no prior failures
    add(300, 0, 1, si=0, ud=0, uh=0, pm=1, label=0)
    add(60,  0, 1, si=0, ud=0, uh=1, pm=1, label=0)   # slightly unusual hour but otherwise clean
    add(40,  1, 2, si=0, ud=0, uh=0, pm=1, label=0)   # 1-2 prior failures — still normal

    # MEDIUM RISK — some anomaly present
    add(120, 2, 3, si=0, ud=0, uh=0, pm=1, label=1)   # a few prior failures
    add(110, 0, 1, si=0, ud=1, uh=0, pm=1, label=1)   # unknown device
    add(90,  0, 1, si=1, ud=0, uh=0, pm=1, label=1)   # rapid attempts
    add(80,  2, 3, si=0, ud=1, uh=1, pm=0, label=1)   # wrong pw + unknown + unusual hour

    # HIGH RISK — brute-force / dictionary attack signatures
    add(250, 4, 10, si=1, ud=0, uh=0, pm=0, label=2)  # rapid repeated failures
    add(200, 4, 10, si=1, ud=1, uh=0, pm=0, label=2)  # + unknown device
    add(150, 4, 10, si=1, ud=1, uh=1, pm=0, label=2)  # + unusual hour
    add(100, 5, 10, si=0, ud=1, uh=1, pm=0, label=2)  # many failures even without rapid interval
    # Attacker who finally guessed the correct password after many attempts
    add(80,  4, 10, si=1, ud=1, uh=0, pm=1, label=2)

    return np.array(rows), np.array(labels)


# ── Training ───────────────────────────────────────────────────────────────────

def train_model():
    os.makedirs("model", exist_ok=True)
    X, y = _make_dataset()
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=8,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_tr, y_tr)

    y_pred = clf.predict(X_te)
    print("\n[ML] Random Forest training complete.")
    print(classification_report(y_te, y_pred, target_names=["low", "medium", "high"]))

    joblib.dump(clf, MODEL_PATH)
    print(f"[ML] Model saved to {MODEL_PATH}\n")

    global _clf_cache
    _clf_cache = clf
    return clf


def ensure_model_ready():
    if not os.path.exists(MODEL_PATH):
        train_model()


# ── Inference ──────────────────────────────────────────────────────────────────

RISK_LABELS = {0: "low", 1: "medium", 2: "high"}


def _load():
    global _clf_cache
    if _clf_cache is None:
        if not os.path.exists(MODEL_PATH):
            return train_model()
        _clf_cache = joblib.load(MODEL_PATH)
    return _clf_cache


def predict_risk(features: dict) -> tuple:
    """Return (risk_level: str, confidence: float)."""
    clf = _load()
    X = np.array([[features[f] for f in FEATURE_NAMES]])
    pred  = int(clf.predict(X)[0])
    proba = clf.predict_proba(X)[0]
    return RISK_LABELS[pred], float(proba[pred])
