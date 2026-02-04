"""
Pytest configuration and fixtures.
"""

import pytest
import asyncio
from typing import Generator, AsyncGenerator

# Configure event loop for async tests
@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_incident_data() -> dict:
    """Sample incident data for testing."""
    return {
        "id": "test-incident-001",
        "title": "Test Malware Detection",
        "description": "Malware detected on workstation WS-001",
        "severity": "high",
        "type": "malware",
        "status": "open",
        "affected_assets": ["ws-001"]
    }


@pytest.fixture
def sample_cve_data() -> dict:
    """Sample CVE data for testing."""
    return {
        "cve_id": "CVE-2024-1234",
        "description": "Test vulnerability",
        "cvss_score": 9.8,
        "severity": "critical",
        "published_date": "2024-01-15",
        "affected_products": ["TestProduct 1.0"],
        "exploit_available": True
    }


@pytest.fixture
def sample_asset_data() -> dict:
    """Sample asset data for testing."""
    return {
        "id": "test-asset-001",
        "name": "Test Server",
        "asset_type": "server",
        "criticality": "high",
        "ip_address": "192.168.1.100",
        "hostname": "test-server.local",
        "zone": "internal"
    }
