"""
Contexta Backend - API Package

This package contains all FastAPI route definitions.
"""

from fastapi import APIRouter

from app.api.routes import (
    auth,
    risks,
    incidents,
    assets,
    agents,
    playbooks,
    ledger,
    twin,
    cves,
    admin,
)

# Main API router
api_router = APIRouter()

# Include all route modules
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(risks.router, prefix="/risks", tags=["Risk Management"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(assets.router, prefix="/assets", tags=["Assets"])
api_router.include_router(agents.router, prefix="/agents", tags=["AI Agents"])
api_router.include_router(playbooks.router, prefix="/playbooks", tags=["Playbooks"])
api_router.include_router(ledger.router, prefix="/ledger", tags=["Audit Ledger"])
api_router.include_router(twin.router, prefix="/twin", tags=["Digital Twin"])
api_router.include_router(cves.router, prefix="/cves", tags=["CVE Management"])
api_router.include_router(admin.router, prefix="/admin", tags=["Admin"])

__all__ = ["api_router"]
