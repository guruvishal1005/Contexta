"""
Contexta Backend - Database Seeder Service

This module handles automatic database seeding with demo data including:
- Demo assets (servers, databases, etc.)
- Real CVEs from NVD/CISA feeds
- AI-enriched risk calculations
- Top 10 risk generation

The seeder runs automatically on startup if the database is empty,
or can be triggered manually via admin endpoint.
"""

import asyncio
import random
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from uuid import UUID
import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetType, ExposureLevel, AssetCriticality
from app.models.cve import CVE
from app.models.risk import Risk, RiskScore, RiskStatus
from app.services.gemini_service import gemini_service, GeminiServiceError
from app.risk_engine.bwvs import BWVSCalculator

logger = structlog.get_logger()


# Demo Assets Configuration - Realistic enterprise assets
DEMO_ASSETS = [
    {
        "name": "Payroll Processing Server",
        "hostname": "payroll-srv-01.internal.corp",
        "ip_address": "10.100.50.10",
        "asset_type": AssetType.SERVER,
        "os": "Windows Server 2022",
        "software": ["ADP Workforce Now", "SQL Server 2019", "IIS 10.0"],
        "exposure_level": ExposureLevel.INTERNAL,
        "criticality": AssetCriticality.PAYMENT_PAYROLL,
        "business_unit": "Finance",
        "owner": "CFO Office",
        "location": "Data Center A",
        "daily_revenue_impact": 15.0,  # 15 Lakhs
    },
    {
        "name": "VPN Gateway",
        "hostname": "vpn-gw-01.edge.corp",
        "ip_address": "203.0.113.10",
        "asset_type": AssetType.NETWORK_DEVICE,
        "os": "Cisco IOS XE 17.6",
        "software": ["Cisco AnyConnect", "RADIUS Client"],
        "exposure_level": ExposureLevel.INTERNET_FACING,
        "criticality": AssetCriticality.CORE_BACKEND,
        "business_unit": "IT Infrastructure",
        "owner": "Network Operations",
        "location": "Edge DC",
        "daily_revenue_impact": 12.0,
    },
    {
        "name": "Customer CRM Database",
        "hostname": "crm-db-01.internal.corp",
        "ip_address": "10.100.30.20",
        "asset_type": AssetType.DATABASE,
        "os": "Ubuntu 22.04 LTS",
        "software": ["PostgreSQL 15", "Redis 7", "PgBouncer"],
        "exposure_level": ExposureLevel.INTERNAL,
        "criticality": AssetCriticality.CRM_HR,
        "business_unit": "Sales",
        "owner": "Sales Operations",
        "location": "Data Center A",
        "daily_revenue_impact": 8.0,
    },
    {
        "name": "Public API Gateway",
        "hostname": "api-gw-01.dmz.corp",
        "ip_address": "203.0.113.50",
        "asset_type": AssetType.APPLICATION,
        "os": "Alpine Linux 3.18",
        "software": ["Kong Gateway", "NGINX", "Node.js 20"],
        "exposure_level": ExposureLevel.INTERNET_FACING,
        "criticality": AssetCriticality.CORE_BACKEND,
        "business_unit": "Engineering",
        "owner": "Platform Team",
        "location": "Cloud - AWS",
        "daily_revenue_impact": 20.0,
    },
    {
        "name": "Authentication Server",
        "hostname": "auth-srv-01.internal.corp",
        "ip_address": "10.100.10.5",
        "asset_type": AssetType.SERVER,
        "os": "RHEL 9",
        "software": ["Keycloak 22", "OpenLDAP", "PostgreSQL 15"],
        "exposure_level": ExposureLevel.VPN,
        "criticality": AssetCriticality.CORE_BACKEND,
        "business_unit": "Security",
        "owner": "Security Operations",
        "location": "Data Center A",
        "daily_revenue_impact": 25.0,
    },
    {
        "name": "CI/CD Pipeline Server",
        "hostname": "jenkins-01.dev.corp",
        "ip_address": "10.200.10.15",
        "asset_type": AssetType.SERVER,
        "os": "Ubuntu 22.04 LTS",
        "software": ["Jenkins 2.426", "Docker", "Kubernetes CLI"],
        "exposure_level": ExposureLevel.INTERNAL,
        "criticality": AssetCriticality.DEV_TEST,
        "business_unit": "Engineering",
        "owner": "DevOps Team",
        "location": "Dev Environment",
        "daily_revenue_impact": 3.0,
    },
    {
        "name": "Email Exchange Server",
        "hostname": "mail-srv-01.internal.corp",
        "ip_address": "10.100.20.10",
        "asset_type": AssetType.SERVER,
        "os": "Windows Server 2022",
        "software": ["Microsoft Exchange 2019", "Outlook Web App"],
        "exposure_level": ExposureLevel.VPN,
        "criticality": AssetCriticality.CRM_HR,
        "business_unit": "IT",
        "owner": "IT Operations",
        "location": "Data Center B",
        "daily_revenue_impact": 5.0,
    },
    {
        "name": "Cloud Storage Service",
        "hostname": "storage-api.cloud.corp",
        "ip_address": "10.50.100.30",
        "asset_type": AssetType.CLOUD_SERVICE,
        "os": "Container (EKS)",
        "software": ["MinIO", "S3 Compatible API", "NGINX"],
        "exposure_level": ExposureLevel.INTERNET_FACING,
        "criticality": AssetCriticality.CORE_BACKEND,
        "business_unit": "Engineering",
        "owner": "Cloud Team",
        "location": "Cloud - AWS",
        "daily_revenue_impact": 10.0,
    },
    {
        "name": "HR Management System",
        "hostname": "hrms-app-01.internal.corp",
        "ip_address": "10.100.40.15",
        "asset_type": AssetType.APPLICATION,
        "os": "RHEL 8",
        "software": ["SAP SuccessFactors Connector", "Java 17", "Tomcat 10"],
        "exposure_level": ExposureLevel.VPN,
        "criticality": AssetCriticality.CRM_HR,
        "business_unit": "Human Resources",
        "owner": "HR Tech",
        "location": "Data Center A",
        "daily_revenue_impact": 4.0,
    },
    {
        "name": "Backup & Recovery Server",
        "hostname": "backup-srv-01.internal.corp",
        "ip_address": "10.100.60.10",
        "asset_type": AssetType.SERVER,
        "os": "Windows Server 2022",
        "software": ["Veeam Backup", "Commvault Agent"],
        "exposure_level": ExposureLevel.ISOLATED,
        "criticality": AssetCriticality.CORE_BACKEND,
        "business_unit": "IT Infrastructure",
        "owner": "Disaster Recovery Team",
        "location": "Backup DC",
        "daily_revenue_impact": 8.0,
    },
    {
        "name": "Web Application Firewall",
        "hostname": "waf-01.edge.corp",
        "ip_address": "203.0.113.20",
        "asset_type": AssetType.NETWORK_DEVICE,
        "os": "F5 BIG-IP 17.1",
        "software": ["F5 Advanced WAF", "iRules LX"],
        "exposure_level": ExposureLevel.INTERNET_FACING,
        "criticality": AssetCriticality.CORE_BACKEND,
        "business_unit": "Security",
        "owner": "Security Operations",
        "location": "Edge DC",
        "daily_revenue_impact": 15.0,
    },
    {
        "name": "Development Database",
        "hostname": "dev-db-01.dev.corp",
        "ip_address": "10.200.30.20",
        "asset_type": AssetType.DATABASE,
        "os": "Ubuntu 22.04 LTS",
        "software": ["MySQL 8.0", "MongoDB 7.0"],
        "exposure_level": ExposureLevel.INTERNAL,
        "criticality": AssetCriticality.DEV_TEST,
        "business_unit": "Engineering",
        "owner": "Development Team",
        "location": "Dev Environment",
        "daily_revenue_impact": 1.0,
    },
    {
        "name": "Monitoring & Observability Platform",
        "hostname": "monitor-01.internal.corp",
        "ip_address": "10.100.70.10",
        "asset_type": AssetType.SERVER,
        "os": "Ubuntu 22.04 LTS",
        "software": ["Prometheus", "Grafana", "AlertManager", "Loki"],
        "exposure_level": ExposureLevel.INTERNAL,
        "criticality": AssetCriticality.CRM_HR,
        "business_unit": "IT Infrastructure",
        "owner": "SRE Team",
        "location": "Data Center A",
        "daily_revenue_impact": 6.0,
    },
    {
        "name": "Container Registry",
        "hostname": "registry.internal.corp",
        "ip_address": "10.100.80.10",
        "asset_type": AssetType.APPLICATION,
        "os": "Container (EKS)",
        "software": ["Harbor", "Docker Registry", "Trivy Scanner"],
        "exposure_level": ExposureLevel.INTERNAL,
        "criticality": AssetCriticality.CORE_BACKEND,
        "business_unit": "Engineering",
        "owner": "Platform Team",
        "location": "Cloud - AWS",
        "daily_revenue_impact": 7.0,
    },
    {
        "name": "ERP Financial Module",
        "hostname": "erp-fin-01.internal.corp",
        "ip_address": "10.100.55.10",
        "asset_type": AssetType.APPLICATION,
        "os": "RHEL 9",
        "software": ["SAP S/4HANA", "SAP HANA DB", "SAP Fiori"],
        "exposure_level": ExposureLevel.VPN,
        "criticality": AssetCriticality.PAYMENT_PAYROLL,
        "business_unit": "Finance",
        "owner": "ERP Team",
        "location": "Data Center A",
        "daily_revenue_impact": 30.0,
    },
]


class DatabaseSeeder:
    """
    Service for seeding the database with demo data.
    
    Handles:
    - Checking if database needs seeding
    - Creating demo assets
    - Fetching real CVEs
    - AI enrichment of CVEs
    - BWVS calculation
    - Risk generation
    """
    
    def __init__(self, db: AsyncSession):
        """Initialize seeder with database session."""
        self.db = db
        self.bwvs_calculator = BWVSCalculator()
        self._enrichment_cache: Dict[str, Dict[str, Any]] = {}
    
    async def needs_seeding(self) -> Tuple[bool, Dict[str, int]]:
        """
        Check if database needs seeding.
        
        Returns:
            Tuple of (needs_seeding, current_counts)
        """
        # Count existing records
        assets_count = await self.db.scalar(select(func.count(Asset.id)))
        cves_count = await self.db.scalar(select(func.count(CVE.id)))
        risks_count = await self.db.scalar(select(func.count(Risk.id)))
        
        counts = {
            "assets": assets_count or 0,
            "cves": cves_count or 0,
            "risks": risks_count or 0,
        }
        
        # Need seeding if risks table is empty (primary indicator)
        needs_seed = risks_count == 0
        
        logger.info(
            "Database seeding check",
            needs_seeding=needs_seed,
            **counts
        )
        
        return needs_seed, counts
    
    async def seed_assets(self) -> List[Asset]:
        """
        Seed demo assets into the database.
        
        Returns:
            List of created Asset models
        """
        logger.info("Seeding demo assets", count=len(DEMO_ASSETS))
        
        created_assets = []
        
        for asset_data in DEMO_ASSETS:
            # Check if asset already exists
            existing = await self.db.scalar(
                select(Asset).where(Asset.hostname == asset_data["hostname"])
            )
            
            if existing:
                logger.debug("Asset already exists", hostname=asset_data["hostname"])
                created_assets.append(existing)
                continue
            
            asset = Asset(**asset_data)
            self.db.add(asset)
            created_assets.append(asset)
            
            logger.debug(
                "Created asset",
                name=asset_data["name"],
                criticality=asset_data["criticality"].value
            )
        
        await self.db.flush()
        logger.info("Demo assets seeded", count=len(created_assets))
        
        return created_assets
    
    async def fetch_and_store_cves(
        self,
        min_cvss: float = 7.0,
        max_count: int = 50,
        days_back: int = 30
    ) -> List[CVE]:
        """
        Fetch real CVEs from NVD/CISA and store them.
        
        Args:
            min_cvss: Minimum CVSS score to include
            max_count: Maximum number of CVEs to fetch
            days_back: Number of days to look back
            
        Returns:
            List of stored CVE models
        """
        from app.ingestion.cve_collector import CVECollector
        
        logger.info(
            "Fetching CVEs",
            min_cvss=min_cvss,
            max_count=max_count,
            days_back=days_back
        )
        
        collector = CVECollector()
        stored_cves = []
        
        try:
            # Fetch from CISA KEV first (known exploited = high priority)
            kev_cves = await collector.fetch_cisa_kev()
            logger.info("Fetched CISA KEV", count=len(kev_cves))
            
            # Fetch from NVD
            nvd_cves = await collector.fetch_nvd_cves(
                days_back=days_back,
                results_per_page=100,
                max_results=max_count * 2  # Fetch more to filter by CVSS
            )
            logger.info("Fetched NVD CVEs", count=len(nvd_cves))
            
            # Combine and deduplicate
            all_cves = {}
            
            # Add NVD CVEs first (they have CVSS scores)
            for cve_data in nvd_cves:
                if cve_data["cvss_score"] >= min_cvss:
                    all_cves[cve_data["cve_id"]] = cve_data
            
            # Add/update with KEV (they are actively exploited - high priority)
            # KEV entries get a default high CVSS if not present
            for cve_data in kev_cves:
                kev_cvss = cve_data.get("cvss_score", 0.0)
                if kev_cvss == 0.0:
                    # Assign high CVSS for known exploited vulnerabilities
                    kev_cvss = 8.5
                
                if cve_data["cve_id"] in all_cves:
                    # Merge KEV data (has_exploit, cisa_kev flags)
                    all_cves[cve_data["cve_id"]].update({
                        "has_exploit": True,
                        "cisa_kev": True,
                        "exploit_sources": ["cisa_kev"]
                    })
                else:
                    # Add KEV entry with default high CVSS
                    cve_data["cvss_score"] = kev_cvss
                    cve_data["has_exploit"] = True
                    cve_data["cisa_kev"] = True
                    cve_data["exploit_sources"] = ["cisa_kev"]
                    all_cves[cve_data["cve_id"]] = cve_data
            
            # Sort by CVSS score and take top N
            sorted_cves = sorted(
                all_cves.values(),
                key=lambda x: (x.get("cisa_kev", False), x["cvss_score"]),
                reverse=True
            )[:max_count]
            
            # Store in database
            for cve_data in sorted_cves:
                # Check if already exists
                existing = await self.db.scalar(
                    select(CVE).where(CVE.cve_id == cve_data["cve_id"])
                )
                
                if existing:
                    stored_cves.append(existing)
                    continue
                
                cve = CVE(
                    cve_id=cve_data["cve_id"],
                    description=cve_data.get("description", "")[:5000],
                    cvss_score=cve_data.get("cvss_score", 0.0),
                    cvss_vector=cve_data.get("cvss_vector"),
                    severity=cve_data.get("severity", "HIGH"),
                    affected_software=cve_data.get("affected_software", []),
                    attack_vector=cve_data.get("attack_vector"),
                    published_date=cve_data.get("published_date"),
                    last_modified=cve_data.get("last_modified"),
                    has_exploit=cve_data.get("has_exploit", False),
                    exploit_sources=cve_data.get("exploit_sources", []),
                    cisa_kev=cve_data.get("cisa_kev", False),
                    references=cve_data.get("references", [])[:10],
                    is_processed=False
                )
                self.db.add(cve)
                stored_cves.append(cve)
                
                logger.debug(
                    "Stored CVE",
                    cve_id=cve_data["cve_id"],
                    cvss=cve_data.get("cvss_score")
                )
            
            await self.db.flush()
            logger.info("CVEs stored", count=len(stored_cves))
            
        except Exception as e:
            logger.error("Failed to fetch CVEs", error=str(e))
            # Continue with fallback data if fetch fails
            stored_cves = await self._create_fallback_cves()
        
        finally:
            await collector.close()
        
        return stored_cves
    
    async def _create_fallback_cves(self) -> List[CVE]:
        """Create fallback CVE data if API fetch fails."""
        logger.warning("Using fallback CVE data")
        
        fallback_cves = [
            {
                "cve_id": "CVE-2024-21887",
                "description": "A command injection vulnerability in Ivanti Connect Secure and Ivanti Policy Secure web components allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.",
                "cvss_score": 9.1,
                "severity": "CRITICAL",
                "affected_software": ["ivanti:connect_secure", "ivanti:policy_secure"],
                "has_exploit": True,
                "cisa_kev": True,
                "exploit_sources": ["cisa_kev", "github"],
            },
            {
                "cve_id": "CVE-2024-1709",
                "description": "ConnectWise ScreenConnect versions prior to 23.9.8 suffer from an authentication bypass vulnerability that allows an attacker to bypass authentication on the server.",
                "cvss_score": 10.0,
                "severity": "CRITICAL",
                "affected_software": ["connectwise:screenconnect"],
                "has_exploit": True,
                "cisa_kev": True,
                "exploit_sources": ["cisa_kev", "exploit-db"],
            },
            {
                "cve_id": "CVE-2024-3400",
                "description": "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software enables an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
                "cvss_score": 10.0,
                "severity": "CRITICAL",
                "affected_software": ["paloaltonetworks:pan-os"],
                "has_exploit": True,
                "cisa_kev": True,
                "exploit_sources": ["cisa_kev", "github"],
            },
            {
                "cve_id": "CVE-2024-20353",
                "description": "A vulnerability in the management and VPN web servers for Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause the device to reload unexpectedly, resulting in a denial of service (DoS) condition.",
                "cvss_score": 8.6,
                "severity": "HIGH",
                "affected_software": ["cisco:adaptive_security_appliance"],
                "has_exploit": True,
                "cisa_kev": True,
                "exploit_sources": ["cisa_kev"],
            },
            {
                "cve_id": "CVE-2024-27198",
                "description": "JetBrains TeamCity before 2023.11.4 allows authentication bypass leading to RCE on TeamCity Server.",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "affected_software": ["jetbrains:teamcity"],
                "has_exploit": True,
                "cisa_kev": True,
                "exploit_sources": ["cisa_kev", "metasploit"],
            },
        ]
        
        stored = []
        for cve_data in fallback_cves:
            existing = await self.db.scalar(
                select(CVE).where(CVE.cve_id == cve_data["cve_id"])
            )
            if existing:
                stored.append(existing)
                continue
            
            cve = CVE(
                cve_id=cve_data["cve_id"],
                description=cve_data["description"],
                cvss_score=cve_data["cvss_score"],
                severity=cve_data["severity"],
                affected_software=cve_data["affected_software"],
                has_exploit=cve_data["has_exploit"],
                cisa_kev=cve_data["cisa_kev"],
                exploit_sources=cve_data["exploit_sources"],
                published_date=datetime.utcnow() - timedelta(days=random.randint(1, 30)),
                is_processed=False
            )
            self.db.add(cve)
            stored.append(cve)
        
        await self.db.flush()
        return stored
    
    async def enrich_cve_with_ai(self, cve: CVE) -> Dict[str, Any]:
        """
        Enrich a CVE with AI-extracted context.
        
        Args:
            cve: CVE to enrich
            
        Returns:
            AI-extracted data dictionary
        """
        # Check cache first
        if cve.cve_id in self._enrichment_cache:
            return self._enrichment_cache[cve.cve_id]
        
        # If already processed, return existing data
        if cve.is_processed and cve.ai_extracted_data:
            return cve.ai_extracted_data
        
        try:
            # Call Gemini for enrichment
            enrichment = await gemini_service.extract_threat_context(cve.description)
            
            # Add exploit maturity estimation
            if cve.cisa_kev:
                enrichment["exploit_maturity"] = "weaponized"
                enrichment["threat_level"] = "active_exploitation"
            elif cve.has_exploit:
                enrichment["exploit_maturity"] = "poc_available"
                enrichment["threat_level"] = "high"
            else:
                enrichment["exploit_maturity"] = "theoretical"
                enrichment["threat_level"] = "medium"
            
            # Calculate relevance percentage based on multiple factors
            base_relevance = 50
            
            # Adjust based on CVSS
            if cve.cvss_score >= 9.0:
                base_relevance += 25
            elif cve.cvss_score >= 7.5:
                base_relevance += 15
            elif cve.cvss_score >= 7.0:
                base_relevance += 10
            
            # Adjust based on exploit status
            if cve.cisa_kev:
                base_relevance += 20
            elif cve.has_exploit:
                base_relevance += 10
            
            enrichment["relevance_percentage"] = min(100, base_relevance)
            
            # Cache and store
            self._enrichment_cache[cve.cve_id] = enrichment
            cve.ai_extracted_data = enrichment
            cve.is_processed = True
            
            logger.debug(
                "CVE enriched with AI",
                cve_id=cve.cve_id,
                relevance=enrichment.get("relevance_percentage")
            )
            
            return enrichment
            
        except GeminiServiceError as e:
            logger.warning("AI enrichment failed, using defaults", cve_id=cve.cve_id, error=str(e))
            # Return sensible defaults
            return self._get_default_enrichment(cve)
        except Exception as e:
            logger.error("Unexpected error in AI enrichment", error=str(e))
            return self._get_default_enrichment(cve)
    
    def _get_default_enrichment(self, cve: CVE) -> Dict[str, Any]:
        """Get default enrichment when AI is unavailable."""
        relevance = 50
        if cve.cvss_score >= 9.0:
            relevance = 85
        elif cve.cvss_score >= 8.0:
            relevance = 70
        elif cve.cvss_score >= 7.0:
            relevance = 60
        
        if cve.cisa_kev:
            relevance = min(100, relevance + 15)
        
        return {
            "exploit_maturity": "weaponized" if cve.cisa_kev else "poc_available" if cve.has_exploit else "theoretical",
            "threat_level": "critical" if cve.cvss_score >= 9.0 else "high" if cve.cvss_score >= 7.0 else "medium",
            "relevance_percentage": relevance,
            "target_software": cve.affected_software or [],
            "attack_vector": cve.attack_vector or "NETWORK",
            "industry": ["technology", "financial", "healthcare"],
            "api_unavailable": True
        }
    
    def match_cve_to_assets(
        self,
        cve: CVE,
        assets: List[Asset],
        enrichment: Dict[str, Any]
    ) -> List[Asset]:
        """
        Match a CVE to relevant assets.
        
        Uses:
        - Software name matching
        - CPE matching
        - AI-suggested targeting
        
        Args:
            cve: CVE to match
            assets: Available assets
            enrichment: AI enrichment data
            
        Returns:
            List of matched assets
        """
        matched = []
        cve_software = set()
        
        # Collect software indicators from CVE
        for sw in cve.affected_software or []:
            # Normalize software name
            sw_lower = sw.lower()
            cve_software.add(sw_lower)
            # Add individual parts
            for part in sw_lower.replace(":", " ").replace("_", " ").split():
                if len(part) > 2:
                    cve_software.add(part)
        
        # Add software from AI enrichment
        for sw in enrichment.get("target_software", []):
            cve_software.add(sw.lower())
        
        # Match against assets
        for asset in assets:
            match_score = 0
            match_reasons = []
            
            # Check software match
            asset_software = " ".join(asset.software or []).lower()
            for sw in cve_software:
                if sw in asset_software or sw in asset.name.lower():
                    match_score += 30
                    match_reasons.append(f"software_match:{sw}")
                    break
            
            # Check OS match
            if asset.os:
                os_lower = asset.os.lower()
                if any(kw in os_lower for kw in ["windows", "linux", "cisco", "palo alto"]):
                    for sw in cve_software:
                        if sw in os_lower:
                            match_score += 25
                            match_reasons.append("os_match")
                            break
            
            # Higher criticality assets get bonus (more likely targets)
            if asset.criticality == AssetCriticality.PAYMENT_PAYROLL:
                match_score += 20
            elif asset.criticality == AssetCriticality.CORE_BACKEND:
                match_score += 15
            
            # Internet-facing assets get bonus for network attacks
            if asset.exposure_level == ExposureLevel.INTERNET_FACING:
                if cve.attack_vector == "NETWORK" or "network" in str(cve_software):
                    match_score += 15
                    match_reasons.append("exposure_match")
            
            # If no specific match, assign based on general relevance
            if match_score == 0:
                # Every CVE should have at least one asset for demo purposes
                if asset.criticality in [AssetCriticality.PAYMENT_PAYROLL, AssetCriticality.CORE_BACKEND]:
                    match_score = 10
            
            if match_score >= 10:
                matched.append((asset, match_score, match_reasons))
        
        # Sort by match score and return top matches
        matched.sort(key=lambda x: x[1], reverse=True)
        
        # Return at least 1 asset, up to 3
        result_assets = [m[0] for m in matched[:3]]
        
        # If no matches, assign to random critical assets
        if not result_assets:
            critical_assets = [
                a for a in assets
                if a.criticality in [AssetCriticality.PAYMENT_PAYROLL, AssetCriticality.CORE_BACKEND]
            ]
            if critical_assets:
                result_assets = random.sample(critical_assets, min(2, len(critical_assets)))
            else:
                result_assets = random.sample(assets, min(2, len(assets)))
        
        return result_assets
    
    async def create_risks(
        self,
        cves: List[CVE],
        assets: List[Asset],
        min_risks: int = 20
    ) -> List[Risk]:
        """
        Create risk records by mapping CVEs to assets and calculating BWVS.
        
        Args:
            cves: List of CVEs
            assets: List of assets
            min_risks: Minimum number of risks to create
            
        Returns:
            List of created Risk models
        """
        logger.info(
            "Creating risks",
            cve_count=len(cves),
            asset_count=len(assets),
            min_risks=min_risks
        )
        
        created_risks = []
        
        for cve in cves:
            # Enrich CVE with AI
            enrichment = await self.enrich_cve_with_ai(cve)
            
            # Add delay to avoid rate limiting
            await asyncio.sleep(0.5)
            
            # Match to assets
            matched_assets = self.match_cve_to_assets(cve, assets, enrichment)
            
            for asset in matched_assets:
                # Check if risk already exists
                existing = await self.db.scalar(
                    select(Risk).where(
                        Risk.cve_id == cve.id,
                        Risk.asset_id == asset.id
                    )
                )
                
                if existing:
                    created_risks.append(existing)
                    continue
                
                # Calculate BWVS
                ai_relevance_pct = enrichment.get("relevance_percentage", 50)
                
                bwvs_result = self.bwvs_calculator.calculate(
                    cvss_score=cve.cvss_score,
                    exploit_activity_score=cve.exploit_activity_score,
                    exposure_score=asset.exposure_score,
                    criticality_score=asset.criticality_score,
                    business_impact_score=asset.business_impact_score,
                    ai_relevance_percentage=ai_relevance_pct
                )
                
                # Determine status
                status = RiskStatus.ACTIVE
                if bwvs_result["final_bwvs"] >= 80:
                    status = RiskStatus.INVESTIGATING
                
                # Generate risk title
                title = self._generate_risk_title(cve, asset, enrichment)
                
                # Create risk
                risk = Risk(
                    title=title,
                    description=self._generate_risk_description(cve, asset, enrichment),
                    cve_id=cve.id,
                    asset_id=asset.id,
                    bwvs_score=bwvs_result["final_bwvs"],
                    priority_score=bwvs_result["final_bwvs"],  # Initial priority = BWVS
                    status=status,
                    ai_relevance_score=ai_relevance_pct,
                    ai_analysis=enrichment,
                    freshness_factor=1.0,
                    trend_factor=1.0 + (0.5 if cve.cisa_kev else 0.0),
                    first_seen=datetime.utcnow() - timedelta(hours=random.randint(1, 72)),
                    last_seen=datetime.utcnow(),
                    remediation_notes=self._generate_remediation_notes(cve, enrichment),
                )
                
                self.db.add(risk)
                # Flush to get the risk.id
                await self.db.flush()
                created_risks.append(risk)
                
                # Also create score history (after flush so risk.id is available)
                risk_score = RiskScore(
                    risk_id=risk.id,
                    cvss_score=bwvs_result["cvss_score"],
                    exploit_activity=bwvs_result["exploit_activity"],
                    exposure_level=bwvs_result["exposure_level"],
                    asset_criticality=bwvs_result["asset_criticality"],
                    business_impact=bwvs_result["business_impact"],
                    ai_relevance=bwvs_result["ai_relevance"],
                    final_bwvs=bwvs_result["final_bwvs"],
                    calculation_timestamp=datetime.utcnow()
                )
                self.db.add(risk_score)
                
                logger.debug(
                    "Created risk",
                    cve_id=cve.cve_id,
                    asset=asset.name,
                    bwvs=bwvs_result["final_bwvs"]
                )
            
            await self.db.flush()
        
        # Mark top 10 risks
        await self._mark_top_10_risks(created_risks)
        
        logger.info("Risks created", count=len(created_risks))
        return created_risks
    
    def _generate_risk_title(
        self,
        cve: CVE,
        asset: Asset,
        enrichment: Dict[str, Any]
    ) -> str:
        """Generate a descriptive risk title."""
        severity = cve.severity or "HIGH"
        exploit_status = "Actively Exploited" if cve.cisa_kev else "Exploitable" if cve.has_exploit else "Vulnerability"
        
        return f"{severity} {exploit_status}: {cve.cve_id} affecting {asset.name}"
    
    def _generate_risk_description(
        self,
        cve: CVE,
        asset: Asset,
        enrichment: Dict[str, Any]
    ) -> str:
        """Generate detailed risk description."""
        desc_parts = [
            f"**Vulnerability**: {cve.cve_id} ({cve.severity}, CVSS {cve.cvss_score})",
            f"\n**Affected Asset**: {asset.name} ({asset.asset_type.value})",
            f"\n**Exposure**: {asset.exposure_level.value.replace('_', ' ').title()}",
            f"\n**Business Criticality**: {asset.criticality.value.replace('_', ' ').title()}",
            f"\n\n**Description**: {cve.description[:500]}...",
        ]
        
        if cve.cisa_kev:
            desc_parts.append("\n\n⚠️ **CISA KEV Alert**: This vulnerability is being actively exploited in the wild.")
        
        if enrichment.get("industry"):
            desc_parts.append(f"\n\n**Target Industries**: {', '.join(enrichment['industry'][:5])}")
        
        return "".join(desc_parts)
    
    def _generate_remediation_notes(
        self,
        cve: CVE,
        enrichment: Dict[str, Any]
    ) -> str:
        """Generate remediation guidance."""
        notes = []
        
        if cve.cisa_kev:
            notes.append("🔴 CRITICAL: Apply vendor patch immediately. This is under active exploitation.")
        else:
            notes.append("⚠️ HIGH PRIORITY: Apply vendor patch within 14 days.")
        
        notes.append("\nRemediation steps:")
        notes.append("1. Identify all affected systems")
        notes.append("2. Test patch in staging environment")
        notes.append("3. Apply patch during maintenance window")
        notes.append("4. Verify patch application")
        notes.append("5. Monitor for anomalous activity")
        
        if cve.references:
            notes.append(f"\n\nReferences: {cve.references[0] if cve.references else 'See NVD'}")
        
        return "\n".join(notes)
    
    async def _mark_top_10_risks(self, risks: List[Risk]) -> None:
        """Mark the top 10 risks by BWVS score."""
        # Reset all top_10 flags
        await self.db.execute(
            Risk.__table__.update().values(is_top_10=False)
        )
        
        # Sort and mark top 10
        sorted_risks = sorted(risks, key=lambda r: r.bwvs_score, reverse=True)
        for risk in sorted_risks[:10]:
            risk.is_top_10 = True
        
        await self.db.flush()
    
    async def run_full_seed(self) -> Dict[str, Any]:
        """
        Run the complete seeding pipeline.
        
        Returns:
            Summary of seeded data
        """
        start_time = datetime.utcnow()
        logger.info("Starting full database seed")
        
        try:
            # 1. Seed assets
            assets = await self.seed_assets()
            
            # 2. Fetch and store CVEs
            cves = await self.fetch_and_store_cves(
                min_cvss=7.0,
                max_count=50,
                days_back=30
            )
            
            # 3. Create risks
            risks = await self.create_risks(cves, assets, min_risks=20)
            
            # Commit all changes
            await self.db.commit()
            
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            
            summary = {
                "success": True,
                "assets_created": len(assets),
                "cves_stored": len(cves),
                "risks_created": len(risks),
                "elapsed_seconds": elapsed,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info("Database seed complete", **summary)
            return summary
            
        except Exception as e:
            logger.error("Database seed failed", error=str(e))
            await self.db.rollback()
            raise
    
    async def clear_and_reseed(self) -> Dict[str, Any]:
        """
        Clear existing data and reseed.
        
        Warning: This deletes all existing risks, CVEs, and assets!
        
        Returns:
            Summary of reseeded data
        """
        logger.warning("Clearing database for reseed")
        
        try:
            # Delete in order of dependencies
            await self.db.execute(RiskScore.__table__.delete())
            await self.db.execute(Risk.__table__.delete())
            await self.db.execute(CVE.__table__.delete())
            await self.db.execute(Asset.__table__.delete())
            await self.db.commit()
            
            logger.info("Database cleared")
            
            # Run fresh seed
            return await self.run_full_seed()
            
        except Exception as e:
            logger.error("Clear and reseed failed", error=str(e))
            await self.db.rollback()
            raise


async def run_startup_seed(db: AsyncSession) -> Optional[Dict[str, Any]]:
    """
    Run seeding on application startup if needed.
    
    Args:
        db: Database session
        
    Returns:
        Seeding summary if seeded, None if skipped
    """
    seeder = DatabaseSeeder(db)
    
    needs_seed, counts = await seeder.needs_seeding()
    
    if not needs_seed:
        logger.info("Database already seeded, skipping", **counts)
        return None
    
    logger.info("Database needs seeding, starting enrichment pipeline")
    return await seeder.run_full_seed()
