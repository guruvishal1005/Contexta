"""
Contexta Backend - Ingestion Package

This package handles data ingestion from external sources:
- CVE Feed Collector (CISA/NVD)
- Fake SIEM Log Generator
"""

from app.ingestion.cve_collector import CVECollector
from app.ingestion.log_generator import FakeLogGenerator

__all__ = ["CVECollector", "FakeLogGenerator"]
