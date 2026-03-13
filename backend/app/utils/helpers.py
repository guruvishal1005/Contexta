"""
Contexta Backend - Helper Utilities

Common utility functions used across the application.
"""

from typing import Any, Optional
from datetime import datetime, timezone
from uuid import uuid4
import json
import structlog

logger = structlog.get_logger()


def generate_uuid() -> str:
    """
    Generate a new UUID string.
    
    Returns:
        UUID as a string
    """
    return str(uuid4())


def utc_now() -> datetime:
    """
    Get current UTC timestamp.
    
    Returns:
        Current datetime in UTC timezone
    """
    return datetime.now(timezone.utc)


def calculate_freshness(
    created_at: datetime,
    half_life_days: float = 7.0
) -> float:
    """
    Calculate freshness score based on age.
    
    Uses exponential decay formula:
    freshness = 0.5 ^ (age_days / half_life_days)
    
    A CVE/threat that is half_life_days old will have a freshness of 0.5.
    
    Args:
        created_at: When the item was created/discovered
        half_life_days: Days after which freshness is 0.5
        
    Returns:
        Freshness score between 0 and 1
    """
    if not created_at:
        return 1.0
    
    now = utc_now()
    
    # Make created_at timezone-aware if it isn't
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    
    age = now - created_at
    age_days = age.total_seconds() / (24 * 60 * 60)
    
    # Exponential decay
    freshness = 0.5 ** (age_days / half_life_days)
    
    return max(0.0, min(1.0, freshness))


def safe_json_loads(
    json_string: str,
    default: Any = None
) -> Any:
    """
    Safely parse a JSON string.
    
    Args:
        json_string: JSON string to parse
        default: Default value if parsing fails
        
    Returns:
        Parsed JSON or default value
    """
    if not json_string:
        return default
    
    try:
        return json.loads(json_string)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning("JSON parse error", error=str(e))
        return default


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate a string to a maximum length.
    
    Args:
        s: String to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated string
    """
    if not s or len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def sanitize_for_log(data: Any, max_depth: int = 3) -> Any:
    """
    Sanitize data for safe logging (remove sensitive fields).
    
    Args:
        data: Data to sanitize
        max_depth: Maximum recursion depth
        
    Returns:
        Sanitized data
    """
    sensitive_keys = {
        "password", "token", "secret", "api_key", "apikey",
        "authorization", "auth", "credential", "credentials"
    }
    
    if max_depth <= 0:
        return "[max depth exceeded]"
    
    if isinstance(data, dict):
        return {
            k: "[REDACTED]" if k.lower() in sensitive_keys else sanitize_for_log(v, max_depth - 1)
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [sanitize_for_log(item, max_depth - 1) for item in data]
    else:
        return data


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds to human readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Human readable duration string
    """
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def parse_cve_id(cve_string: str) -> Optional[tuple]:
    """
    Parse a CVE ID into year and number components.
    
    Args:
        cve_string: CVE ID string (e.g., "CVE-2024-1234")
        
    Returns:
        Tuple of (year, number) or None if invalid
    """
    import re
    
    pattern = r'^CVE-(\d{4})-(\d+)$'
    match = re.match(pattern, cve_string.upper())
    
    if match:
        return (int(match.group(1)), int(match.group(2)))
    return None


def severity_to_number(severity: str) -> int:
    """
    Convert severity string to numeric value for sorting.
    
    Args:
        severity: Severity string (critical, high, medium, low)
        
    Returns:
        Numeric severity value (higher = more severe)
    """
    severity_map = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
        "informational": 0
    }
    return severity_map.get(severity.lower(), 2)


def number_to_severity(number: int) -> str:
    """
    Convert numeric severity to string.
    
    Args:
        number: Numeric severity value
        
    Returns:
        Severity string
    """
    severity_map = {
        4: "critical",
        3: "high",
        2: "medium",
        1: "low",
        0: "info"
    }
    return severity_map.get(number, "medium")
