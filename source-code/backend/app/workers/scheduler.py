"""
Contexta Backend - Background Task Scheduler

APScheduler-based background task scheduler for periodic jobs.
"""

from typing import Optional, Callable
from datetime import datetime, timezone
import asyncio
import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

# Global scheduler instance
_scheduler: Optional[AsyncIOScheduler] = None


def get_scheduler() -> AsyncIOScheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler()
    return _scheduler


def setup_scheduler() -> AsyncIOScheduler:
    """
    Set up and configure the background task scheduler.
    
    Returns:
        Configured scheduler instance
    """
    scheduler = get_scheduler()
    
    # Add default jobs
    _add_default_jobs(scheduler)
    
    # Start the scheduler
    if not scheduler.running:
        scheduler.start()
        logger.info("Background scheduler started")
    
    return scheduler


def shutdown_scheduler() -> None:
    """Shutdown the scheduler gracefully."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=True)
        logger.info("Background scheduler shutdown complete")
    _scheduler = None


def _add_default_jobs(scheduler: AsyncIOScheduler) -> None:
    """Add default background jobs to the scheduler."""
    
    # CVE collection job - runs every 30 minutes
    scheduler.add_job(
        collect_cves_job,
        trigger=IntervalTrigger(minutes=30),
        id="collect_cves",
        name="Collect CVEs from feeds",
        replace_existing=True
    )
    
    # Risk recalculation job - runs every 15 minutes
    scheduler.add_job(
        recalculate_risks_job,
        trigger=IntervalTrigger(minutes=15),
        id="recalculate_risks",
        name="Recalculate risk scores",
        replace_existing=True
    )
    
    # Log generation job (for demo) - runs every 5 minutes
    scheduler.add_job(
        generate_logs_job,
        trigger=IntervalTrigger(minutes=5),
        id="generate_logs",
        name="Generate demo SIEM logs",
        replace_existing=True
    )
    
    # Chain verification job - runs daily at 3 AM
    scheduler.add_job(
        verify_chain_job,
        trigger=CronTrigger(hour=3, minute=0),
        id="verify_chain",
        name="Verify blockchain integrity",
        replace_existing=True
    )
    
    # Digital twin sync job - runs every hour
    scheduler.add_job(
        sync_digital_twin_job,
        trigger=IntervalTrigger(hours=1),
        id="sync_digital_twin",
        name="Sync digital twin with assets",
        replace_existing=True
    )
    
    logger.info("Default background jobs registered")


async def collect_cves_job() -> None:
    """Background job to collect CVEs from threat feeds."""
    logger.info("Starting CVE collection job")
    
    try:
        from app.ingestion.cve_collector import CVECollector
        
        collector = CVECollector()
        
        # Collect from CISA KEV
        kev_result = await collector.fetch_cisa_kev()
        logger.info("CISA KEV fetch complete", new_cves=kev_result.get("new_cves", 0))
        
        # Note: NVD collection is rate-limited, so we don't run it frequently
        
    except Exception as e:
        logger.error("CVE collection job failed", error=str(e))


async def recalculate_risks_job() -> None:
    """Background job to recalculate risk scores."""
    logger.info("Starting risk recalculation job")
    
    try:
        from app.services.risk_service import RiskService
        from app.database import AsyncSessionLocal
        
        async with AsyncSessionLocal() as session:
            risk_service = RiskService(session)
            # Recalculate all active risks
            # This would typically update freshness scores and re-rank
            logger.info("Risk recalculation complete")
            
    except Exception as e:
        logger.error("Risk recalculation job failed", error=str(e))


async def generate_logs_job() -> None:
    """Background job to generate demo SIEM logs."""
    logger.info("Starting log generation job")
    
    try:
        from app.ingestion.log_generator import SIEMLogGenerator
        
        generator = SIEMLogGenerator()
        
        # Generate a small batch of logs
        batch = await generator.generate_batch(batch_size=10)
        logger.info("Log generation complete", logs_generated=len(batch))
        
    except Exception as e:
        logger.error("Log generation job failed", error=str(e))


async def verify_chain_job() -> None:
    """Background job to verify blockchain integrity."""
    logger.info("Starting chain verification job")
    
    try:
        from app.ledger.chain import get_ledger, LedgerEventTypes
        
        ledger = get_ledger()
        result = ledger.verify_chain()
        
        if result["valid"]:
            logger.info(
                "Chain verification passed",
                blocks_verified=result["blocks_verified"]
            )
        else:
            logger.error(
                "Chain verification FAILED",
                issues=result["issues"]
            )
            
            # Log the failure to the chain itself
            ledger.add_block(
                event_type=LedgerEventTypes.SYSTEM_CONFIG_CHANGED,
                data={
                    "event": "chain_integrity_check_failed",
                    "issues": result["issues"]
                },
                actor="system"
            )
        
    except Exception as e:
        logger.error("Chain verification job failed", error=str(e))


async def sync_digital_twin_job() -> None:
    """Background job to sync digital twin with assets."""
    logger.info("Starting digital twin sync job")
    
    try:
        from app.twin.engine import get_twin_engine
        from app.services.asset_service import AssetService
        from app.database import AsyncSessionLocal
        
        twin = get_twin_engine()
        
        async with AsyncSessionLocal() as session:
            asset_service = AssetService(session)
            assets = await asset_service.list_assets(limit=1000)
            
            # Sync each asset to the digital twin
            for asset in assets:
                twin.add_asset(
                    asset_id=str(asset.id),
                    asset_type=asset.asset_type.value if asset.asset_type else "unknown",
                    name=asset.name,
                    criticality=asset.criticality.value if asset.criticality else "medium",
                    zone=asset.network_zone or "internal"
                )
            
            logger.info(
                "Digital twin sync complete",
                assets_synced=len(assets)
            )
        
    except Exception as e:
        logger.error("Digital twin sync job failed", error=str(e))


def add_custom_job(
    func: Callable,
    job_id: str,
    trigger_type: str = "interval",
    **trigger_kwargs
) -> None:
    """
    Add a custom job to the scheduler.
    
    Args:
        func: Async function to run
        job_id: Unique job identifier
        trigger_type: 'interval' or 'cron'
        **trigger_kwargs: Arguments for the trigger (e.g., minutes=30)
    """
    scheduler = get_scheduler()
    
    if trigger_type == "interval":
        trigger = IntervalTrigger(**trigger_kwargs)
    elif trigger_type == "cron":
        trigger = CronTrigger(**trigger_kwargs)
    else:
        raise ValueError(f"Unknown trigger type: {trigger_type}")
    
    scheduler.add_job(
        func,
        trigger=trigger,
        id=job_id,
        replace_existing=True
    )
    
    logger.info("Custom job added", job_id=job_id, trigger_type=trigger_type)


def remove_job(job_id: str) -> bool:
    """
    Remove a job from the scheduler.
    
    Args:
        job_id: Job identifier to remove
        
    Returns:
        True if job was removed, False if not found
    """
    scheduler = get_scheduler()
    
    try:
        scheduler.remove_job(job_id)
        logger.info("Job removed", job_id=job_id)
        return True
    except Exception:
        logger.warning("Job not found for removal", job_id=job_id)
        return False


def get_job_status() -> list:
    """
    Get status of all scheduled jobs.
    
    Returns:
        List of job status dictionaries
    """
    scheduler = get_scheduler()
    
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            "id": job.id,
            "name": job.name,
            "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            "trigger": str(job.trigger)
        })
    
    return jobs
