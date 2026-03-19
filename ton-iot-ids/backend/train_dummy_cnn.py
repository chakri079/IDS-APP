
# =================================================================
# TON-IoT IDS - Dummy CNN-BiLSTM Model (To match User Architecture)
# =================================================================

import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import numpy as np
import pandas as pd
import joblib
import pickle
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Conv1D, BatchNormalization, MaxPooling1D,
    Dropout, Bidirectional, LSTM, Dense, Layer
)
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import StandardScaler

# Ensure directory exists
if not os.path.exists("model"):
    os.makedirs("model")

print("🔹 TF Version:", tf.__version__)

# ============================================================
# FEATURES & DUMMY DATA
# ============================================================

FEATURES = [
    "src_port", "dst_port", "proto", "service", "duration", "src_bytes", "dst_bytes",
    "conn_state", "missed_bytes", "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes",
    "dns_query", "dns_qclass", "dns_qtype", "dns_rcode", "http_trans_depth", "http_method",
    "http_uri", "http_version", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
    "weird_name", "weird_addl", "weird_notice", "label", "type", "attack"
]

N_SAMPLES = 200
np.random.seed(42)

# Generate realistic-ish ranges
data = {
    "src_port": np.random.randint(0, 65535, N_SAMPLES),
    "dst_port": np.random.randint(0, 65535, N_SAMPLES),
    "proto": np.random.randint(0, 255, N_SAMPLES),
    "service": np.random.randint(0, 10, N_SAMPLES),
    "duration": np.random.exponential(1.0, N_SAMPLES),
    "src_bytes": np.random.exponential(500, N_SAMPLES),
    "dst_bytes": np.random.exponential(500, N_SAMPLES),
    # ... fill others with random junk
}

# Fill rest with generic random
for f in FEATURES:
    if f not in data:
        data[f] = np.random.randint(0, 100, N_SAMPLES)

df = pd.DataFrame(data)

# Save feature names
with open("model/feature_names.pkl", "wb") as f:
    pickle.dump(FEATURES, f)
print("✅ Feature names saved.")

# Scale
scaler = StandardScaler()
X = scaler.fit_transform(df[FEATURES])
joblib.dump(scaler, "model/scaler.pkl")
print("✅ Scaler saved.")

# Reshape (Samples, Features, 1)
N_FEATURES = len(FEATURES)
X = X.reshape(-1, N_FEATURES, 1)

# Labels (Random)
y = np.random.randint(0, 2, N_SAMPLES)

# ============================================================
# MODEL DEFINITION (USER'S ARCHITECTURE)
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
        config = super().get_config()
        return config

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
    x = AttentionLayer()(x) # <--- The requested attention layer

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

print("🚀 Building User's CNN-BiLSTM Model...")
model = build_model()
model.summary()

print("🚀 Training Dummy Model (1 Epoch)...")
model.fit(X, y, epochs=1, batch_size=32, verbose=1)

model.save("model/ton_iot_model.h5")
print("✅ CNN-BiLSTM Dummy Model Saved to model/ton_iot_model.h5")
