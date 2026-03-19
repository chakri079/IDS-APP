
# ============================================================
# TON-IoT IDS - Dummy Neural Network (MLP) Model (Fallback)
# ============================================================

import os
import joblib
import pickle
import numpy as np
import pandas as pd
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

# Ensure features match frontend
FEATURES = [
    "src_port", "dst_port", "proto", "service", "duration", "src_bytes", "dst_bytes",
    "conn_state", "missed_bytes", "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes",
    "dns_query", "dns_qclass", "dns_qtype", "dns_rcode", "http_trans_depth", "http_method",
    "http_uri", "http_version", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
    "weird_name", "weird_addl", "weird_notice", "label", "type", "attack"
]

if not os.path.exists("model"):
    os.makedirs("model")

print("Generating dummy data with REALISTIC ranges...")
np.random.seed(42)
N = 200

# Create a dictionary of arrays
data = {}
for f in FEATURES:
    if "port" in f:
        data[f] = np.random.randint(0, 65535, N)
    elif "proto" in f:
        data[f] = np.random.randint(0, 255, N)
    elif "bytes" in f:
        data[f] = np.random.exponential(1000, N)
    elif "duration" in f:
        data[f] = np.random.exponential(10, N)
    else:
        data[f] = np.random.randint(0, 100, N)

df = pd.DataFrame(data, columns=FEATURES)

# 2. Save Feature Names
with open("model/feature_names.pkl", "wb") as f:
    pickle.dump(FEATURES, f)

# 3. Train Scaler
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df)
joblib.dump(scaler, "model/scaler.pkl")

# Generate target: simplistic rule for demo
# If src_port > 1024 (non-privileged) -> Normal (0), else Attack (1) ?
# Let's make it random but seeded for stability
y = np.random.randint(0, 2, N)

# 4. Train Model (MLP - Neural Network)
print("Training MLP Neural Network...")
model = MLPClassifier(hidden_layer_sizes=(64, 32), activation='relu', solver='adam', max_iter=500, random_state=42)
model.fit(X_scaled, y)
joblib.dump(model, "model/model.pkl")

print("✅ Neural Network (MLP) Dummy Model Saved.")
