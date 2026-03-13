
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
from datetime import datetime

app = FastAPI(title="Contexta Mock Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "contexta-mock"}

@app.get("/api/v1/health")
async def health_v1():
    return {"status": "healthy", "service": "contexta-mock"}

@app.get("/api/v1/risks/top10")
async def get_top10():
    return {
        "risks": [
            {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "title": "Critical Vulnerability in Payroll Server",
                "description": "CVE-2024-1709 Authentication Bypass detected on Payroll-srv-01",
                "bwvs_score": 92.5,
                "priority_score": 98.2,
                "status": "active",
                "ai_relevance_score": 95.0,
                "ai_analysis": {"threat_level": "critical", "impact": "high"},
                "first_seen": datetime.utcnow().isoformat(),
                "last_seen": datetime.utcnow().isoformat(),
                "is_top_10": True,
                "asset_data": {"name": "Payroll Processing Server", "criticality": "payment_payroll"},
                "cve_data": {"cve_id": "CVE-2024-1709", "cvss_score": 10.0}
            }
        ],
        "last_calculated": datetime.utcnow().isoformat(),
        "calculation_interval_minutes": 5
    }

@app.get("/api/v1/auth/me")
async def get_me():
    return {"id": "user-123", "username": "admin", "full_name": "Admin User", "role": "admin"}

@app.get("/", tags=["Root"])
async def root():
    return {"name": "Contexta Mock", "version": "1.0.0"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
