
# ============================================================
# TON-IoT IDS - Dummy Random Forest Model (Fallback)
# ============================================================

import os
import joblib
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
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

# 1. Create Dummy Data
print("Generating dummy data...")
X = np.random.rand(100, len(FEATURES))
y = np.random.randint(0, 2, 100)
df = pd.DataFrame(X, columns=FEATURES)

# 2. Save Feature Names
with open("model/feature_names.pkl", "wb") as f:
    pickle.dump(FEATURES, f)

# 3. Train Scaler
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df)
joblib.dump(scaler, "model/scaler.pkl")

# 4. Train Model
model = RandomForestClassifier(n_estimators=10)
model.fit(X_scaled, y)
joblib.dump(model, "model/model.pkl")

print("✅ Random Forest Dummy Model Saved.")
