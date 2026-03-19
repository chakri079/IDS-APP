
# ============================================================
# TON-IoT IDS - Random Forest Training Script (Multi-Class)
# Predicts: normal | backdoor | ddos | dos | injection |
#           mitm | password | ransomware | scanning | xss
# ============================================================

import os
import numpy as np
import pandas as pd
import random
import warnings
import joblib
import pickle

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from imblearn.over_sampling import SMOTE
from collections import Counter

warnings.filterwarnings("ignore")

# ============================================================
# CONFIGURATION
# ============================================================

DATA_PATH          = "ton-iot.csv"
MODEL_PATH         = "model/model.pkl"
SCALER_PATH        = "model/scaler.pkl"
FEATURE_NAMES_PATH = "model/feature_names.pkl"
ENCODERS_PATH      = "model/label_encoders.pkl"
CLASS_NAMES_PATH   = "model/class_names.pkl"   # NEW: stores class label list
SEED               = 42

np.random.seed(SEED)
random.seed(SEED)


def train_and_save():
    if not os.path.exists("model"):
        os.makedirs("model")

    # --- 1. Load Data ---
    if not os.path.exists(DATA_PATH):
        print(f"[ERROR] '{DATA_PATH}' not found.")
        return

    print("[INFO] Loading TON-IoT dataset...")
    df = pd.read_csv(DATA_PATH)
    df.columns = df.columns.str.strip()
    print(f"[INFO] Shape: {df.shape}")
    print(f"[INFO] Columns: {df.columns.tolist()}")

    # --- 2. Build multi-class label from 'type' column ---
    if "type" not in df.columns:
        print("[ERROR] 'type' column not found in dataset.")
        return

    df["type"] = df["type"].astype(str).str.strip().str.lower()
    print(f"[INFO] Unique attack types: {sorted(df['type'].unique())}")
    print(f"[INFO] Class distribution:\n{df['type'].value_counts()}")

    # Encode the target
    target_le = LabelEncoder()
    y = target_le.fit_transform(df["type"])
    class_names = target_le.classes_.tolist()
    print(f"[INFO] Class mapping: {dict(enumerate(class_names))}")

    # Save class names for inference
    with open(CLASS_NAMES_PATH, "wb") as f:
        pickle.dump(class_names, f)
    print(f"[SUCCESS] Class names saved: {class_names}")

    # --- 3. Remove leaky / non-feature columns ---
    drop_cols = ["label", "attack", "type", "src_ip", "dst_ip",
                 "weird_name", "weird_notice", "conn_state", "http_status_code"]
    for col in drop_cols:
        if col in df.columns:
            df.drop(columns=col, inplace=True)

    X = df.copy()

    # --- 4. Encode categoricals ---
    object_cols = X.select_dtypes(include=["object"]).columns.tolist()
    label_encoders = {}
    for col in object_cols:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        label_encoders[col] = le

    with open(ENCODERS_PATH, "wb") as f:
        pickle.dump(label_encoders, f)
    print(f"[INFO] Label encoders saved for: {list(label_encoders.keys())}")

    # --- 5. Clean & Save feature metadata ---
    X = X.apply(pd.to_numeric, errors="coerce")
    X.fillna(X.median(), inplace=True)

    feature_names = X.columns.tolist()
    with open(FEATURE_NAMES_PATH, "wb") as f:
        pickle.dump(feature_names, f)
    print(f"[INFO] Feature names saved ({len(feature_names)} features).")

    # --- 6. Split & Scale ---
    X_train, X_test, y_train, y_test = train_test_split(
        X.values, y, test_size=0.2, random_state=SEED, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)
    joblib.dump(scaler, SCALER_PATH)
    print("[INFO] Scaler saved.")

    # --- 7. SMOTE (only if minority class has enough samples) ---
    print("[INFO] Handling class imbalance with SMOTE...")
    counts = Counter(y_train)
    minority_count = min(counts.values())
    print(f"[INFO] Smallest class count: {minority_count}")
    
    if minority_count > 5:
        k = min(5, minority_count - 1)
        sm = SMOTE(random_state=SEED, k_neighbors=k)
        X_train, y_train = sm.fit_resample(X_train, y_train)
        print(f"[INFO] After SMOTE: {Counter(y_train)}")
    else:
        print("[WARNING] Skipping SMOTE: too few samples in minority class.")

    # --- 8. Train Multi-Class Random Forest ---
    print("[INFO] Training Random Forest (multi-class)...")
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=25,
        min_samples_split=5,
        n_jobs=-1,
        random_state=SEED,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)

    # --- 9. Save & Evaluate ---
    joblib.dump(model, MODEL_PATH)
    print(f"[SUCCESS] Model saved to {MODEL_PATH}")

    y_pred = model.predict(X_test)
    print(f"\n[INFO] Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("[INFO] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=class_names))
    print("[SUCCESS] Training complete.")


if __name__ == "__main__":
    train_and_save()
