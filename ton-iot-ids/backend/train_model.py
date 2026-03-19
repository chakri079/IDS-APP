
# ============================================================
# TON-IoT IDS - CNN-BiLSTM-Attention Training Script
# Trains on REAL ton-iot.csv dataset
# ============================================================

import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"   # Force CPU — avoids GPU DLL errors on this machine
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import numpy as np
import pandas as pd
import random
import warnings
import joblib
import pickle

warnings.filterwarnings("ignore")

import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Conv1D, BatchNormalization, MaxPooling1D,
    Dropout, Bidirectional, LSTM, Dense, Layer
)
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.optimizers import Adam

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
from collections import Counter

# ============================================================
# CONFIGURATION
# ============================================================

DATA_PATH   = "ton-iot.csv"
MODEL_PATH  = "model/ton_iot_model.h5"
SCALER_PATH = "model/scaler.pkl"
FEATURE_NAMES_PATH = "model/feature_names.pkl"
ENCODERS_PATH      = "model/label_encoders.pkl"
SEED       = 42
EPOCHS     = 30
BATCH_SIZE = 256
NOISE_STD  = 0.01

tf.random.set_seed(SEED)
np.random.seed(SEED)
random.seed(SEED)

# ============================================================
# ATTENTION LAYER
# ============================================================

class AttentionLayer(Layer):
    def build(self, input_shape):
        self.W = self.add_weight(
            name="attention_weight",
            shape=(input_shape[-1],),
            initializer="glorot_uniform",
            trainable=True
        )
        super().build(input_shape)

    def call(self, x):
        e = tf.nn.tanh(x)
        e = tf.tensordot(e, self.W, axes=1)
        a = tf.nn.softmax(e, axis=1)
        a = tf.expand_dims(a, -1)
        return tf.reduce_sum(x * a, axis=1)

    def get_config(self):
        return super().get_config()

# ============================================================
# MAIN TRAINING FUNCTION
# ============================================================

def train_and_save():
    # --- 1. Load Data ---
    if not os.path.exists(DATA_PATH):
        if os.path.exists(f"../{DATA_PATH}"):
            file_path = f"../{DATA_PATH}"
        else:
            print(f"❌ Error: '{DATA_PATH}' not found.")
            return
    else:
        file_path = DATA_PATH

    print("📂 Loading TON-IoT dataset...")
    df = pd.read_csv(file_path)
    df.columns = df.columns.str.strip()
    print(f"   Shape: {df.shape}")
    print(f"   Columns: {list(df.columns)}")

    # --- 2. Build label ---
    if "label" in df.columns:
        df["label"] = df["label"].apply(
            lambda x: 0 if str(x).strip().lower() in ["normal", "benign", "0"] else 1
        )
    elif "type" in df.columns:
        df["label"] = df["type"].apply(
            lambda x: 0 if str(x).strip().lower() == "normal" else 1
        )
    elif "attack" in df.columns:
        df["label"] = df["attack"].apply(
            lambda x: 0 if str(x).strip().lower() == "normal" else 1
        )
    else:
        raise ValueError("❌ No valid label column found.")

    print(f"\n📊 Label distribution:")
    vc = df["label"].value_counts()
    print(f"   Normal (0): {vc.get(0, 0)}")
    print(f"   Attack (1): {vc.get(1, 0)}")

    y = df["label"].values

    # --- 3. Remove leaky / identifier features ---
    leaky = ["label", "attack", "type", "src_ip", "dst_ip",
             "weird_name", "weird_notice", "conn_state", "http_status_code"]
    for col in leaky:
        if col in df.columns:
            df.drop(columns=col, inplace=True)

    print(f"\n🚫 Leaky features removed. Remaining columns: {len(df.columns)}")

    X = df.copy()

    # --- 4. Encode categoricals & save encoders ---
    object_cols = X.select_dtypes(include=["object"]).columns.tolist()
    print(f"\n🔤 Categorical columns: {object_cols}")

    label_encoders = {}
    for col in object_cols:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        label_encoders[col] = le

    with open(ENCODERS_PATH, "wb") as f:
        pickle.dump(label_encoders, f)
    print(f"✅ Label encoders saved to {ENCODERS_PATH}")

    # --- 5. Numeric conversion & cleaning ---
    X = X.apply(pd.to_numeric, errors="coerce")
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(X.median(), inplace=True)
    X = X.clip(lower=-1e6, upper=1e6)
    print("✅ Data cleaned.")

    # --- 6. Save feature names ---
    feature_names = X.columns.tolist()
    with open(FEATURE_NAMES_PATH, "wb") as f:
        pickle.dump(feature_names, f)
    print(f"✅ Feature names saved ({len(feature_names)} features): {feature_names}")

    # --- 7. Train / test split ---
    X_train, X_test, y_train, y_test = train_test_split(
        X.values, y, test_size=0.2, random_state=SEED, stratify=y
    )

    # --- 8. Scaling ---
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)
    joblib.dump(scaler, SCALER_PATH)
    print(f"✅ Scaler saved to {SCALER_PATH}")

    # --- 9. SMOTE (adaptive) ---
    print("\n⚖️ Handling class imbalance with SMOTE...")
    minority = min(Counter(y_train).values())
    if minority > 1:
        k = min(5, minority - 1)
        sm = SMOTE(random_state=SEED, k_neighbors=k)
        X_train, y_train = sm.fit_resample(X_train, y_train)
        print(f"   After SMOTE — Normal: {sum(y_train==0)}, Attack: {sum(y_train==1)}")
    else:
        print("   ⚠️ SMOTE skipped (not enough minority samples).")

    # Gaussian noise augmentation
    X_train += np.random.normal(0, NOISE_STD, X_train.shape)

    # --- 10. Reshape for CNN ---
    N_FEATURES = X_train.shape[1]
    X_train = X_train.reshape(-1, N_FEATURES, 1)
    X_test  = X_test.reshape(-1,  N_FEATURES, 1)

    # --- 11. Build CNN-BiLSTM-Attention model ---
    def build_model():
        inp = Input(shape=(N_FEATURES, 1))

        x = Conv1D(64, 3, activation="relu", padding="same")(inp)
        x = BatchNormalization()(x)
        x = MaxPooling1D(2)(x)
        x = Dropout(0.3)(x)

        x = Conv1D(128, 3, activation="relu", padding="same")(x)
        x = BatchNormalization()(x)
        x = MaxPooling1D(2)(x)
        x = Dropout(0.4)(x)

        x = Bidirectional(LSTM(128, return_sequences=True))(x)
        x = AttentionLayer()(x)

        x = Dense(64, activation="relu")(x)
        x = Dropout(0.4)(x)
        out = Dense(1, activation="sigmoid")(x)

        model = Model(inp, out)
        model.compile(
            optimizer=Adam(learning_rate=5e-4),
            loss="binary_crossentropy",
            metrics=["accuracy"]
        )
        return model

    print("\n🚀 Building CNN-BiLSTM-Attention model...")
    model = build_model()
    model.summary()

    # --- 12. Training ---
    callbacks = [
        EarlyStopping(patience=5, restore_best_weights=True, verbose=1),
        ReduceLROnPlateau(patience=3, factor=0.5, min_lr=1e-6, verbose=1)
    ]

    print("\n🚀 Training on real TON-IoT data...")
    history = model.fit(
        X_train, y_train,
        validation_split=0.1,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        callbacks=callbacks,
        verbose=2
    )

    # --- 13. Save model ---
    model.save(MODEL_PATH)
    print(f"\n✅ Model saved to {MODEL_PATH}")

    # --- 14. Evaluation ---
    print("\n🔍 Evaluating on test set...")
    y_prob = model.predict(X_test, batch_size=BATCH_SIZE).ravel()
    y_pred = (y_prob > 0.5).astype(int)

    acc = accuracy_score(y_test, y_pred)
    try:
        auc = roc_auc_score(y_test, y_prob)
    except Exception:
        auc = float("nan")

    print(f"\n  Accuracy : {acc:.4f}")
    print(f"  AUC      : {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\n✅ Training complete.")


if __name__ == "__main__":
    os.makedirs("model", exist_ok=True)
    train_and_save()
