"""
Contexta Backend - Main Application

The main FastAPI application entry point.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog
import time

from app.config import get_settings
from app.database import init_db
from app.api import api_router
from app.utils.logging import setup_logging
from app.workers.scheduler import setup_scheduler, shutdown_scheduler

# Configure logging
setup_logging()
logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    
    Handles startup and shutdown events.
    """
    # Startup
    logger.info("Starting Contexta Backend", version="1.0.0")
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Run startup seeding if database is empty
    try:
        from app.database import AsyncSessionLocal
        from app.services.seeder import run_startup_seed
        
        async with AsyncSessionLocal() as db:
            seed_result = await run_startup_seed(db)
            if seed_result:
                logger.info(
                    "Startup seeding completed",
                    assets=seed_result["assets_created"],
                    cves=seed_result["cves_stored"],
                    risks=seed_result["risks_created"]
                )
            else:
                logger.info("Database already seeded, skipping startup seed")
    except Exception as e:
        logger.error("Startup seeding failed", error=str(e))
        # Continue startup even if seeding fails
    
    # Start background scheduler
    setup_scheduler()
    logger.info("Background scheduler started")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Contexta Backend")
    
    # Stop scheduler
    shutdown_scheduler()
    logger.info("Background scheduler stopped")


# Create FastAPI application
app = FastAPI(
    title="Contexta",
    description="""
    **Contexta** - Autonomous Context-Aware Threat Intelligence & Business Risk Platform
    
    ## Features
    
    - **CVE Feed Collector**: Ingests from CISA KEV and NVD
    - **SIEM Log Generator**: Generates realistic security event logs
    - **BWVS Scoring**: Business-Weighted Vulnerability Scoring
    - **Top-10 Risks**: Real-time prioritized risk dashboard
    - **Multi-Agent Analysis**: AI-powered SOC agents (Analyst, Intel, Forensics, Business, Response)
    - **Digital Twin**: NetworkX-based network simulation with attack path analysis
    - **Blockchain Ledger**: Immutable audit logging
    - **Playbook Engine**: Automated response workflows
    
    ## BWVS Formula
    
    ```
    BWVS = (CVSS×0.20 + Exploit×0.20 + Exposure×0.15 + Asset_Crit×0.20 + Business_Impact×0.15 + AI_Relevance×0.10) × 10
    ```
    
    ## Priority Formula
    
    ```
    Priority = BWVS × Freshness × TrendFactor
    ```
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add request processing time to response headers."""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(round(process_time * 1000, 2))
    return response


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle unhandled exceptions."""
    logger.error(
        "Unhandled exception",
        path=request.url.path,
        method=request.method,
        error=str(exc)
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "type": type(exc).__name__
        }
    )


# Include API router
app.include_router(api_router, prefix="/api")


# Health check endpoints
@app.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint.
    
    Returns basic service status.
    """
    return {
        "status": "healthy",
        "service": "contexta",
        "version": "1.0.0"
    }


@app.get("/health/detailed", tags=["Health"])
async def detailed_health_check():
    """
    Detailed health check with component status.
    """
    from app.database import async_engine
    from app.ledger.chain import get_ledger
    from app.twin.engine import get_twin_engine
    from sqlalchemy import text
    
    components = {}
    
    # Check database
    try:
        async with async_engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        components["database"] = {"status": "healthy"}
    except Exception as e:
        components["database"] = {"status": "unhealthy", "error": str(e)}
    
    # Check ledger
    try:
        ledger = get_ledger()
        verification = ledger.verify_chain()
        components["ledger"] = {
            "status": "healthy" if verification["valid"] else "degraded",
            "blocks": len(ledger.chain),
            "integrity": verification["valid"]
        }
    except Exception as e:
        components["ledger"] = {"status": "unhealthy", "error": str(e)}
    
    # Check digital twin
    try:
        twin = get_twin_engine()
        components["digital_twin"] = {
            "status": "healthy",
            "nodes": twin.graph.number_of_nodes(),
            "edges": twin.graph.number_of_edges()
        }
    except Exception as e:
        components["digital_twin"] = {"status": "unhealthy", "error": str(e)}
    
    # Determine overall status
    all_healthy = all(c.get("status") == "healthy" for c in components.values())
    
    return {
        "status": "healthy" if all_healthy else "degraded",
        "service": "contexta",
        "version": "1.0.0",
        "components": components
    }


@app.get("/", tags=["Root"])
async def root():
    """
    Root endpoint with API information.
    """
    return {
        "name": "Contexta",
        "description": "Autonomous Context-Aware Threat Intelligence & Business Risk Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "api_prefix": "/api"
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
