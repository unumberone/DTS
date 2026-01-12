from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from utils import save_data, load_data, detect_malware, get_overview_stats, get_model_performance
import shutil
import os
import datetime
import random

from dotenv import load_dotenv
import os

# Load env vars
load_dotenv()

app = FastAPI()

# Get base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Mount static files for model images
app.mount("/static/cnn_lstm", StaticFiles(directory=os.path.join(BASE_DIR, "CNN_LSTM")), name="cnn_lstm_static")
app.mount("/static/lstm", StaticFiles(directory=os.path.join(BASE_DIR, "LSTM")), name="lstm_static")
app.mount("/static/transformer", StaticFiles(directory=os.path.join(BASE_DIR, "Transformer")), name="transformer_static")

# Đoạn này để config CORS cho frontend gọi vào
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Malware Detection API is running"}

import tempfile

# Directory to store uploaded files temporarily
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    from utils import detect_malware_with_model
    
    # Save uploaded file to disk
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    file_bytes = await file.read()
    with open(file_path, "wb") as f:
        f.write(file_bytes)
    
    # Run analysis with file bytes
    scan_result = detect_malware_with_model(file.filename, "cnn_lstm", file_bytes)
    save_data(scan_result)
    return scan_result

from fastapi import Form

@app.post("/api/scan")
async def api_scan_file(file: UploadFile = File(...), method: str = Form("hybrid"), mode: str = Form("quick")):
    from scan_cache import get_cache, compute_sha256
    from hybrid_engine import hybrid_engine_instance, AnalysisMethod
    from utils import save_data
    from fastapi.concurrency import run_in_threadpool
    import datetime
    import random
    
    # 1. Read file and compute hash
    # Reading file into memory is still synchronous IO bound here but relatively fast for small files
    # For very large files, this should be chunked, but let's stick to simple "read()" for now.
    file_bytes = await file.read()
    
    # Run CPU-bound hashing in threadpool too?
    # sha256 = compute_sha256(file_bytes) 
    # Actually, compute_sha256 is fast enough usually, 
    # but let's put the whole analysis block in threadpool if possible or just the heavy part.
    
    sha256 = compute_sha256(file_bytes)
    
    # 2. Check Cache
    cache = get_cache()
    # Cache key includes method AND mode
    cache_key_method = f"{method}_{mode}"
    cached_result = cache.get(sha256, cache_key_method)
    
    if cached_result:
        print(f"[API] Returning CACHED result for {file.filename} (method={method}, mode={mode})")
        return cached_result
    
    # 3. Analyze using Hybrid Engine
    print(f"[API] Analyzing {file.filename} with method={method}, mode={mode}...")
    try:
        scan_result = await run_in_threadpool(hybrid_engine_instance.analyze, file_bytes, file.filename, method, mode=mode)
        
        # Add timestamps and ID
        scan_result["id"] = str(random.randint(10000, 99999))
        scan_result["timestamp"] = datetime.datetime.now().isoformat()
        
        # 4. Legacy Compatibility
        if mode == "deep" and "deep_static" in scan_result["results"]:
             # For deep mode, the summary comes from deep_static
             deep = scan_result["results"]["deep_static"]
             primary_verdict = deep["verdict"]
             primary_conf = deep["risk_score"]
        else:
             # Standard logic (copied from existing)
             results_dict = scan_result.get("results", {})
             if "hybrid" in results_dict:
                 res = results_dict["hybrid"]
             elif "rule_only" in results_dict:
                 res = results_dict["rule_only"]
             elif method in results_dict:
                 res = results_dict[method]
             else:
                 res = {}
                 
             primary_verdict = res.get("verdict", "UNKNOWN") if res else "UNKNOWN"
             primary_conf = res.get("risk_score", 0) if res else 0

        legacy_record = {
            "id": scan_result["id"],
            "filename": file.filename,
            "type": scan_result.get("file", {}).get("file_type", file.filename.split('.')[-1] if '.' in file.filename else "unknown"),
            "file_size": len(file_bytes),
            "result": "Benign" if primary_verdict == "CLEAN" else primary_verdict,
            "confidence": primary_conf,
            "details": f"Mode: {mode.upper()} | Method: {method}",
            "timestamp": scan_result["timestamp"],
            "uploader": "admin"
        }
        save_data(legacy_record)

        # 5. Cache and Return
        cache.set(sha256, cache_key_method, scan_result, len(file_bytes), file.filename)
        return scan_result
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"errors": [str(e)], "results": {}}

@app.get("/history")
def get_history():
    return load_data()

# --- New Endpoints for Full Integration ---

@app.get("/api/overview")
def get_overview_api():
    return get_overview_stats()

@app.get("/api/threats")
def get_threats_api():
    data = load_data()
    # Filter for threats? The frontend threats page seems to show a list. 
    # Let's return all data or just threats.
    # The frontend expects a list.
    return [d for d in data if d.get('result') in ['Malicious', 'Suspicious']]

@app.get("/api/threats/{id}")
def get_threat_detail(id: str):
    data = load_data()
    for d in data:
        if d.get('id') == id:
            return d
    return {"error": "Threat not found"}

from pydantic import BaseModel
from typing import List, Optional

# --- Settings & Support Mocks ---

class ApiKeyRequest(BaseModel):
    name: str

class WebhookRequest(BaseModel):
    enabled: bool
    endpoint: str
    secret: str
    events: List[str]

class TicketRequest(BaseModel):
    category: str
    subject: str
    priority: str
    description: str

@app.get("/api/settings")
def get_settings():
    return {
        "apiKeys": [{"id": "1", "name": "Default Key", "status": "Active", "valueMasked": "sk-****9876", "createdAt": "2024-01-01"}],
        "webhooks": {"enabled": False, "endpoint": "", "secret": "", "events": []}
    }

@app.post("/api/settings/api-keys")
def upsert_api_key(req: ApiKeyRequest):
    # Mock generating a key
    new_key = {
        "id": str(random.randint(100,999)),
        "name": req.name,
        "status": "Active",
        "valueMasked": f"sk-****{random.randint(1000,9999)}",
        "createdAt": datetime.datetime.now().strftime("%Y-%m-%d")
    }
    return {
        "apiKeys": [new_key, {"id": "1", "name": "Default Key", "status": "Active", "valueMasked": "sk-****9876", "createdAt": "2024-01-01"}],
        "generatedKeyValue": f"sk-{random.randint(100000,999999)}-SECRET"
    }

@app.put("/api/settings/webhooks")
def update_webhooks(req: WebhookRequest):
    return {
        "webhooks": req.dict()
    }

@app.get("/api/support/hub")
def get_support_hub():
    return {
        "announcements": [
            {"id": 1, "title": "System Update v2.0", "date": "2024-03-15", "isNew": True},
            {"id": 2, "title": "Maintenance Schedule", "date": "2024-03-10", "isNew": False}
        ],
        "tickets": [],
        "chat": {"available": True}
    }

@app.get("/api/support/kb/search")
def search_kb(q: str):
    # Mock KB search
    return {
        "items": [
            {"id": 101, "title": f"How to resolve '{q}' errors", "snippet": "Common steps to debug this issue...", "tags": ["troubleshooting"]},
            {"id": 102, "title": "Understanding Scan Results", "snippet": "Explanation of benign vs malicious...", "tags": ["guide"]}
        ]
    }

@app.post("/api/support/tickets")
def create_ticket(req: TicketRequest):
    new_ticket = {
        "id": str(random.randint(5000, 9999)),
        "subject": req.subject,
        "status": "open",
        "updatedAt": "Just now"
    }
    return {"ticket": new_ticket}

@app.get("/api/models/{model_key}/analytics")
def get_model_analytics(model_key: str):
    # Return the detailed performance report from utils for the selected model
    return get_model_performance(model_key)

# Ensure existing endpoints work for new paths if frontend calls /api/...
@app.get("/api/logs")
def get_logs_api():
    # Frontend Log.jsx calls /api/logs
    return load_data()


if __name__ == "__main__":
    import uvicorn
    # Đoạn này để chạy server
    uvicorn.run(app, host="0.0.0.0", port=8000)
