"""
Contexta Backend - CVE Feed Collector

This module collects CVE data from CISA KEV and NVD APIs.
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()


class CVECollector:
    """
    CVE Feed Collector for CISA KEV and NVD APIs.
    
    Collects vulnerability data and normalizes it to internal schema.
    
    Sources:
    - CISA Known Exploited Vulnerabilities (KEV)
    - NVD (National Vulnerability Database) API 2.0
    """
    
    def __init__(self):
        """Initialize collector with API configuration."""
        self.nvd_api_url = settings.nvd_api_url
        self.nvd_api_key = settings.nvd_api_key
        self.cisa_kev_url = settings.cisa_kev_url
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client
    
    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def fetch_cisa_kev(self) -> List[Dict[str, Any]]:
        """
        Fetch CISA Known Exploited Vulnerabilities catalog.
        
        Returns:
            List of CVE data dictionaries
        """
        logger.info("Fetching CISA KEV catalog")
        client = await self._get_client()
        
        try:
            response = await client.get(self.cisa_kev_url)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            normalized = []
            for vuln in vulnerabilities:
                normalized.append(self._normalize_cisa_kev(vuln))
            
            logger.info("Fetched CISA KEV", count=len(normalized))
            return normalized
            
        except httpx.HTTPError as e:
            logger.error("Failed to fetch CISA KEV", error=str(e))
            return []
        except Exception as e:
            logger.error("Error processing CISA KEV", error=str(e))
            return []
    
    def _normalize_cisa_kev(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize CISA KEV entry to internal schema.
        
        Args:
            vuln: Raw CISA KEV vulnerability data
            
        Returns:
            Normalized CVE dictionary
        """
        cve_id = vuln.get("cveID", "")
        
        return {
            "cve_id": cve_id,
            "description": vuln.get("shortDescription", ""),
            "cvss_score": 0.0,  # CISA KEV doesn't include CVSS, will be enriched from NVD
            "cvss_vector": None,
            "severity": "HIGH",  # KEV entries are high severity by default
            "affected_software": [
                f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}"
            ],
            "attack_vector": None,
            "published_date": self._parse_date(vuln.get("dateAdded")),
            "last_modified": datetime.utcnow(),
            "has_exploit": True,  # All KEV entries have known exploits
            "exploit_sources": ["cisa_kev"],
            "cisa_kev": True,
            "references": [],
        }
    
    async def fetch_nvd_cves(
        self,
        days_back: int = 7,
        results_per_page: int = 100,
        max_results: int = 500
    ) -> List[Dict[str, Any]]:
        """
        Fetch recent CVEs from NVD API.
        
        Args:
            days_back: Number of days to look back
            results_per_page: Results per API call
            max_results: Maximum total results
            
        Returns:
            List of CVE data dictionaries
        """
        logger.info("Fetching NVD CVEs", days_back=days_back)
        client = await self._get_client()
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": results_per_page,
            "startIndex": 0
        }
        
        # Add API key if available
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        
        all_cves = []
        
        try:
            while len(all_cves) < max_results:
                response = await client.get(
                    self.nvd_api_url,
                    params=params,
                    headers=headers
                )
                response.raise_for_status()
                
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    break
                
                for vuln in vulnerabilities:
                    normalized = self._normalize_nvd_cve(vuln)
                    if normalized:
                        all_cves.append(normalized)
                
                # Check if there are more results
                total_results = data.get("totalResults", 0)
                if params["startIndex"] + results_per_page >= total_results:
                    break
                
                params["startIndex"] += results_per_page
                
                # Rate limiting - NVD API has limits
                await asyncio.sleep(0.6 if self.nvd_api_key else 6.0)
            
            logger.info("Fetched NVD CVEs", count=len(all_cves))
            return all_cves
            
        except httpx.HTTPError as e:
            logger.error("Failed to fetch NVD CVEs", error=str(e))
            return all_cves  # Return what we have so far
        except Exception as e:
            logger.error("Error processing NVD CVEs", error=str(e))
            return all_cves
    
    def _normalize_nvd_cve(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize NVD CVE entry to internal schema.
        
        Args:
            vuln: Raw NVD vulnerability data
            
        Returns:
            Normalized CVE dictionary or None
        """
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        
        if not cve_id.startswith("CVE-"):
            return None
        
        # Get description
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Get CVSS score
        cvss_score = 0.0
        cvss_vector = None
        severity = "MEDIUM"
        attack_vector = None
        
        metrics = cve.get("metrics", {})
        
        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = cvss_data.get("baseSeverity", "MEDIUM")
                attack_vector = cvss_data.get("attackVector", None)
                break
        
        # Get affected software (CPE)
        affected_software = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpe = cpe_match.get("criteria", "")
                        # Extract product name from CPE
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            affected_software.append(f"{vendor}:{product}")
        
        # Get references
        references = []
        for ref in cve.get("references", []):
            references.append(ref.get("url", ""))
        
        # Check for exploit tags
        has_exploit = False
        exploit_sources = []
        for ref in cve.get("references", []):
            tags = ref.get("tags", [])
            url = ref.get("url", "").lower()
            
            if "Exploit" in tags:
                has_exploit = True
                if "github.com" in url:
                    exploit_sources.append("github")
                elif "exploit-db.com" in url:
                    exploit_sources.append("exploit-db")
                elif "packetstorm" in url:
                    exploit_sources.append("packetstorm")
                else:
                    exploit_sources.append("other")
        
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "affected_software": list(set(affected_software)),
            "attack_vector": attack_vector,
            "published_date": self._parse_date(cve.get("published")),
            "last_modified": self._parse_date(cve.get("lastModified")),
            "has_exploit": has_exploit,
            "exploit_sources": list(set(exploit_sources)),
            "cisa_kev": False,
            "references": references[:10],  # Limit references
        }
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str.split("Z")[0], fmt)
            except ValueError:
                continue
        
        return None
    
    async def collect_all(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """
        Collect CVEs from all sources and merge.
        
        Args:
            days_back: Days to look back for NVD
            
        Returns:
            Merged and deduplicated CVE list
        """
        logger.info("Starting full CVE collection")
        
        # Fetch from both sources concurrently
        kev_task = self.fetch_cisa_kev()
        nvd_task = self.fetch_nvd_cves(days_back=days_back)
        
        kev_cves, nvd_cves = await asyncio.gather(kev_task, nvd_task)
        
        # Merge and deduplicate, preferring KEV data
        cve_map = {}
        
        # Add NVD CVEs first
        for cve in nvd_cves:
            cve_map[cve["cve_id"]] = cve
        
        # Overlay KEV data (marks as exploited)
        for cve in kev_cves:
            cve_id = cve["cve_id"]
            if cve_id in cve_map:
                # Merge KEV data into NVD entry
                cve_map[cve_id]["cisa_kev"] = True
                cve_map[cve_id]["has_exploit"] = True
                if "cisa_kev" not in cve_map[cve_id].get("exploit_sources", []):
                    cve_map[cve_id].setdefault("exploit_sources", []).append("cisa_kev")
            else:
                # Add KEV-only entry
                cve_map[cve_id] = cve
        
        all_cves = list(cve_map.values())
        
        # Sort by CVSS score descending
        all_cves.sort(key=lambda c: c.get("cvss_score", 0), reverse=True)
        
        logger.info(
            "CVE collection complete",
            total=len(all_cves),
            kev_count=len(kev_cves),
            nvd_count=len(nvd_cves)
        )
        
        return all_cves
    
    async def fetch_specific_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a specific CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            
        Returns:
            CVE data or None
        """
        logger.info("Fetching specific CVE", cve_id=cve_id)
        client = await self._get_client()
        
        params = {"cveId": cve_id}
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        
        try:
            response = await client.get(
                self.nvd_api_url,
                params=params,
                headers=headers
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if vulnerabilities:
                return self._normalize_nvd_cve(vulnerabilities[0])
            
            return None
            
        except Exception as e:
            logger.error("Failed to fetch CVE", cve_id=cve_id, error=str(e))
            return None
