
# ============================================================
# TON-IoT IDS - Dummy Model Generator (For Demo)
# ============================================================

import os
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
from sklearn.preprocessing import StandardScaler

# Ensure model directory exists
if not os.path.exists("model"):
    os.makedirs("model")

# Define features matching Frontend (FeatureForm.jsx)
FEATURES = [
    "src_port", "dst_port", "proto", "service", "duration", "src_bytes", "dst_bytes",
    "conn_state", "missed_bytes", "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes",
    "dns_query", "dns_qclass", "dns_qtype", "dns_rcode", "http_trans_depth", "http_method",
    "http_uri", "http_version", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
    "weird_name", "weird_addl", "weird_notice", "label", "type", "attack"
]

# Create dummy data
N_SAMPLES = 100
data = np.random.rand(N_SAMPLES, len(FEATURES))
df = pd.DataFrame(data, columns=FEATURES)

# Save feature names
with open("model/feature_names.pkl", "wb") as f:
    pickle.dump(FEATURES, f)
print("✅ Dummy feature names saved.")

# Create Scaler
scaler = StandardScaler()
X = scaler.fit_transform(df)
joblib.dump(scaler, "model/scaler.pkl")
print("✅ Dummy scaler saved.")

# Reshape for model
X = X.reshape(X.shape[0], X.shape[1], 1)

# Define Custom Attention Layer (Must match app.py)
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

# Build Model
def build_model():
    inp = Input(shape=(len(FEATURES), 1))
    x = Conv1D(32, 3, activation="relu", padding="same")(inp)
    x = BatchNormalization()(x)
    x = MaxPooling1D(2)(x)
    x = Dropout(0.2)(x) # Reduced dropout for dummy
    
    x = Bidirectional(LSTM(32, return_sequences=True))(x)
    x = AttentionLayer()(x) # Custom layer
    
    x = Dense(32, activation="relu")(x)
    out = Dense(1, activation="sigmoid")(x)
    
    model = Model(inp, out)
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

model = build_model()
# Train on dummy data for 1 epoch just to initialize weights
y = np.random.randint(0, 2, N_SAMPLES)
model.fit(X, y, epochs=1, verbose=1)

model.save("model/ton_iot_model.h5")
print("✅ Dummy model saved.")
