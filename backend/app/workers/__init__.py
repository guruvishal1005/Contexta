"""
Contexta Backend - Workers Package

This package contains background task workers using APScheduler.
"""

from app.workers.scheduler import (
    setup_scheduler,
    get_scheduler,
    shutdown_scheduler,
)

__all__ = [
    "setup_scheduler",
    "get_scheduler",
    "shutdown_scheduler",
]
