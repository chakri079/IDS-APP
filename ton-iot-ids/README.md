# TON-IoT Intrusion Detection System

A web-based Intrusion Detection System (IDS) that uses a CNN-BiLSTM model to classify network traffic as Normal or Attack. The system accepts manual feature inputs and provides a real-time risk assessment.

## Project Structure

```
ton-iot-ids/
├── backend/            # FastAPI Backend
│   ├── model/          # Saved ML Model & Scaler
│   ├── app.py          # API Server
│   ├── train_model.py  # Training Script
│   └── requirements.txt
├── frontend/           # React Frontend
│   ├── src/            # Source Code
│   └── package.json
└── README.md
```

## Setup & Running

### 1. Backend

The backend serves the ML model via a REST API.

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Train the model (Using Dummy Random Forest due to missing dataset)
# python train_model.py # Use this if you have ton-iot.csv
python train_dummy_rf.py

# Run the API server
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.

### 2. Frontend

The frontend provides a cyber-themed dashboard for interaction.

```bash
cd frontend

# Install dependencies
npm install

# Run the development server
npm run dev
```

Open your browser at `http://localhost:5173`.

## Usage

1. Open the Frontend dashboard.
2. Enter network feature values in the form or paste a JSON object.
3. Click **ANALYZE TRAFFIC**.
4. View the prediction (Normal/Attack), probability score, and risk level.

### Example Input JSON

```json
{
  "src_port": 80,
  "dst_port": 443,
  "proto": 6,
  "service": 0,
  "duration": 1.5,
  "src_bytes": 120,
  "dst_bytes": 450,
  "conn_state": 0,
  "missed_bytes": 0,
  "src_pkts": 5,
  "src_ip_bytes": 300,
  "dst_pkts": 4,
  "dst_ip_bytes": 200,
  "dns_query": 0,
  "dns_qclass": 0,
  "dns_qtype": 0,
  "dns_rcode": 0,
  "http_trans_depth": 0,
  "http_method": 0,
  "http_uri": 0,
  "http_version": 0,
  "http_user_agent": 0,
  "http_orig_mime_types": 0,
  "http_resp_mime_types": 0,
  "weird_name": 0,
  "weird_addl": 0,
  "weird_notice": 0,
  "label": 0,
  "type": 0,
  "attack": 0
}
```

## Stack

- **Backend**: Python, FastAPI, TensorFlow/Keras, Scikit-learn
- **Frontend**: React, Vite, Tailwind CSS, Framer Motion
- **Model**: CNN + BiLSTM + Attention Mechanism
