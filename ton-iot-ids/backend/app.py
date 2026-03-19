
# ============================================================
# TON-IoT IDS - Backend API  (Multi-Class Threat Detection)
# Predicts: normal | backdoor | ddos | dos | injection |
#           mitm | password | ransomware | scanning | xss
# ============================================================

import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import pickle
import numpy as np # type: ignore
import pandas as pd # type: ignore
import joblib # type: ignore
from fastapi import FastAPI, HTTPException # type: ignore
from pydantic import BaseModel # type: ignore
from fastapi.middleware.cors import CORSMiddleware # type: ignore
from typing import Dict, Any
import google.generativeai as genai # type: ignore
from dotenv import load_dotenv # type: ignore

# Load environment variables from .env file
load_dotenv()

# Configure Gemini
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", ""))


# ============================================================
# PATHS
# ============================================================

RF_MODEL_PATH      = "model/model.pkl"
SCALER_PATH        = "model/scaler.pkl"
FEATURE_NAMES_PATH = "model/feature_names.pkl"
ENCODERS_PATH      = "model/label_encoders.pkl"
CLASS_NAMES_PATH   = "model/class_names.pkl"

# ============================================================
# Threat metadata for richer response
# ============================================================

THREAT_META = {
    "normal":     {"icon": "✅", "severity": "None",     "color": "green",  "description": "Normal traffic — no threat detected."},
    "backdoor":   {"icon": "🚪", "severity": "Critical", "color": "red",    "description": "Backdoor access attempt detected."},
    "ddos":       {"icon": "💥", "severity": "High",     "color": "orange", "description": "Distributed Denial-of-Service attack."},
    "dos":        {"icon": "⛔", "severity": "High",     "color": "orange", "description": "Denial-of-Service attack."},
    "injection":  {"icon": "💉", "severity": "High",     "color": "red",    "description": "Injection attack (SQL/Command/etc.)."},
    "mitm":       {"icon": "🕵️", "severity": "Critical", "color": "red",    "description": "Man-in-the-Middle attack."},
    "password":   {"icon": "🔑", "severity": "High",     "color": "orange", "description": "Password brute-force/cracking attack."},
    "ransomware": {"icon": "💰", "severity": "Critical", "color": "red",    "description": "Ransomware activity detected."},
    "scanning":   {"icon": "🔍", "severity": "Medium",   "color": "yellow", "description": "Network scanning / port scan."},
    "xss":        {"icon": "📜", "severity": "Medium",   "color": "yellow", "description": "Cross-Site Scripting (XSS) attack."},
}

# ============================================================
# FastAPI App
# ============================================================

app = FastAPI(title="TON-IoT IDS API", version="4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class NetworkFlow(BaseModel):
    features: Dict[str, Any]

class ThreatContext(BaseModel):
    threat_type: str

# ============================================================
# GLOBAL VARIABLES
# ============================================================

model          = None
scaler         = None
feature_names  = None
label_encoders = {}
class_names    = []   # e.g. ['backdoor','ddos','dos',...]

# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def load_all():
    global model, scaler, feature_names, label_encoders, class_names

    print("[INFO] Loading model artefacts...")

    try:
        if os.path.exists(SCALER_PATH):
            scaler = joblib.load(SCALER_PATH)
            print("[INFO] Scaler loaded.")

        if os.path.exists(FEATURE_NAMES_PATH):
            with open(FEATURE_NAMES_PATH, "rb") as f:
                feature_names = pickle.load(f)
            print(f"[INFO] Feature names loaded ({len(feature_names)} features).")

        if os.path.exists(ENCODERS_PATH):
            with open(ENCODERS_PATH, "rb") as f:
                label_encoders = pickle.load(f)
            print(f"[INFO] Label encoders loaded for: {list(label_encoders.keys())}")

        if os.path.exists(CLASS_NAMES_PATH):
            with open(CLASS_NAMES_PATH, "rb") as f:
                class_names = pickle.load(f)
            print(f"[INFO] Class names loaded: {class_names}")

        if os.path.exists(RF_MODEL_PATH):
            model = joblib.load(RF_MODEL_PATH)
            print("[SUCCESS] Random Forest multi-class model loaded.")
        else:
            print("[ERROR] No model found! Please run train_model_rf.py first.")

    except Exception as e:
        print(f"[CRITICAL] Loading error: {e}")

# ============================================================
# HELPERS
# ============================================================

def safe_encode(col_name: str, value) -> int:
    le = label_encoders.get(col_name)
    if le is None or not hasattr(le, 'transform'):
        return 0
    try:
        return int(le.transform([str(value)])[0]) # type: ignore
    except:
        return 0

# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/")
def home():
    return {
        "status": "Running",
        "model_version": "4.0 (Multi-Class)",
        "features": len(feature_names) if feature_names else 0,
        "classes": class_names
    }

@app.get("/classes")
def get_classes():
    """Return the list of detectable threat types."""
    return {"classes": class_names}

@app.post("/predict")
def predict(flow: NetworkFlow):
    global model, scaler, feature_names, label_encoders, class_names

    if model is None or scaler is None or feature_names is None:
        raise HTTPException(status_code=503, detail="Model, scaler, or feature names not loaded. Run train_model_rf.py first.")

    try:
        data = flow.features

        # Check if empty (all numeric values are 0, and all strings are default '-' or 'tcp')
        is_empty = True
        for k, v in data.items():
            if str(v) not in ["0", "0.0", "-", "", "tcp"]:
                is_empty = False
                break
                
        if is_empty:
            return {
                "prediction": "Normal",
                "threat_type": "normal",
                "threat_icon": "✅",
                "threat_description": "Awaiting valid and substantial feature inputs.",
                "severity": "None",
                "probability": 1.0,
                "risk_level": "None",
                "class_probabilities": {"normal": 1.0, "attack": 0.0},
                "model_used": "Baseline Check"
            }

        # Build feature vector in the exact order the model was trained on
        assert feature_names is not None
        row = []
        for feat in feature_names:
            val = data.get(feat, 0)
            if feat in label_encoders:
                val = safe_encode(feat, val)
            row.append(val)

        X = pd.DataFrame([row], columns=feature_names)
        X = X.apply(pd.to_numeric, errors="coerce").fillna(0)
        assert scaler is not None
        X_scaled = scaler.transform(X.values)

        # Multi-class prediction
        assert model is not None
        pred_idx   = int(model.predict(X_scaled)[0])
        proba      = model.predict_proba(X_scaled)[0]  # shape: (n_actual_classes,)
        n_proba    = len(proba)

        # Guard: clamp pred_idx to the actual proba array size
        pred_idx   = min(pred_idx, n_proba - 1)
        confidence = float(proba[pred_idx])

        # Resolve predicted type — use class_names when lengths align, else fallback
        if class_names and len(class_names) == n_proba:
            predicted_type = class_names[pred_idx]
        elif class_names and pred_idx < len(class_names):
            predicted_type = class_names[pred_idx]
        else:
            # Binary fallback: 0 = normal, 1 = attack
            predicted_type = "normal" if pred_idx == 0 else "scanning"

        is_attack = predicted_type != "normal"

        # Encode full probability distribution (use actual proba length)
        if class_names and len(class_names) == n_proba:
            class_proba = {class_names[i]: float(f"{float(proba[i]):.4f}") for i in range(n_proba)}
        else:
            # Binary fallback labels
            labels = class_names if len(class_names) == n_proba else ["normal", "attack"]
            class_proba = {labels[i] if i < len(labels) else str(i): float(f"{float(proba[i]):.4f}") for i in range(n_proba)}

        # Threat metadata
        meta = THREAT_META.get(predicted_type, {
            "icon": "⚠️", "severity": "Unknown", "color": "gray", "description": "Unknown threat type."
        })

        # Risk level based on confidence × severity
        if not is_attack:
            risk_level = "None"
        elif meta["severity"] == "Critical" and confidence > 0.7:
            risk_level = "Critical"
        elif meta["severity"] in ("Critical", "High") and confidence > 0.4:
            risk_level = "High"
        elif meta["severity"] == "Medium" or confidence > 0.3:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return {
            "prediction":      "Attack" if is_attack else "Normal",
            "threat_type":     predicted_type,          # e.g. "ddos", "xss", "normal"
            "threat_icon":     meta["icon"],
            "threat_description": meta["description"],
            "severity":        meta["severity"],
            "probability":     float(f"{confidence:.4f}"),   # confidence of predicted class
            "risk_level":      risk_level,
            "class_probabilities": class_proba,         # full distribution
            "model_used":      "RandomForest-MultiClass"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/precautions")
def get_precautions(threat: ThreatContext):
    if not os.environ.get("GEMINI_API_KEY"):
        return {"precautions": "GEMINI_API_KEY environment variable is not set locally. Please paste your key into the .env file in the backend folder, then restart the server to get AI-powered precautions."}
        
    try:
        llm = genai.GenerativeModel('models/gemini-2.5-flash')
        prompt = f"Provide 3 short, actionable precautions to mitigate a '{threat.threat_type}' network attack. Format as a simple list without asterisks or markdown styling."
        response = llm.generate_content(prompt)
        return {"precautions": response.text}
    except Exception as e:
        return {"precautions": f"Failed to fetch precautions: {str(e)}"}

if __name__ == "__main__":
    import uvicorn # type: ignore
    uvicorn.run(app, host="0.0.0.0", port=8000)
