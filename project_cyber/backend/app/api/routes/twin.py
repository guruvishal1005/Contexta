"""
Contexta Backend - Digital Twin Routes

Provides endpoints for digital twin simulation and attack path analysis.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
import structlog

from app.twin.engine import get_twin_engine
from app.auth.jwt import get_current_user_optional, TokenData

logger = structlog.get_logger()
router = APIRouter()


@router.get("/stats")
async def get_twin_stats(
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Get digital twin network statistics.
    """
    twin = get_twin_engine()
    
    # Initialize sample network if empty
    if twin.graph.number_of_nodes() == 0:
        twin.initialize_sample_network()
    
    return twin.get_network_stats()


@router.get("/export")
async def export_twin(
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Export the digital twin graph data.
    """
    twin = get_twin_engine()
    
    return twin.export_to_dict()


@router.post("/import")
async def import_twin(
    data: Dict[str, Any] = Body(...),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Import digital twin graph data.
    """
    twin = get_twin_engine()
    
    twin.import_from_dict(data)
    
    logger.info(
        "Digital twin imported",
        user_id=current_user.user_id,
        nodes=twin.graph.number_of_nodes()
    )
    
    return {"message": "Digital twin imported", "stats": twin.get_network_stats()}


@router.post("/assets")
async def add_asset_to_twin(
    asset_id: str,
    asset_type: str,
    name: str,
    criticality: str = "medium",
    zone: str = "internal",
    metadata: Optional[Dict[str, Any]] = None,
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Add an asset to the digital twin.
    """
    twin = get_twin_engine()
    
    twin.add_asset(
        asset_id=asset_id,
        asset_type=asset_type,
        name=name,
        criticality=criticality,
        zone=zone,
        metadata=metadata
    )
    
    return {"message": "Asset added", "asset_id": asset_id}


@router.post("/connections")
async def add_connection(
    source_id: str,
    target_id: str,
    connection_type: str = "network",
    protocols: Optional[List[str]] = None,
    bidirectional: bool = False,
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Add a connection between assets.
    """
    twin = get_twin_engine()
    
    twin.add_connection(
        source_id=source_id,
        target_id=target_id,
        connection_type=connection_type,
        protocols=protocols or ["tcp"],
        bidirectional=bidirectional
    )
    
    return {"message": "Connection added", "source": source_id, "target": target_id}


@router.post("/vulnerabilities")
async def add_vulnerability(
    asset_id: str,
    cve_id: str,
    cvss_score: float,
    exploitable: bool = False,
    network_exploitable: bool = False,
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Add a vulnerability to an asset in the digital twin.
    """
    twin = get_twin_engine()
    
    twin.add_vulnerability(
        asset_id=asset_id,
        cve_id=cve_id,
        cvss_score=cvss_score,
        exploitable=exploitable,
        network_exploitable=network_exploitable
    )
    
    return {"message": "Vulnerability added", "asset_id": asset_id, "cve_id": cve_id}


@router.get("/attack-paths/bfs")
async def find_attack_paths_bfs(
    start_id: str,
    target_id: str,
    max_depth: int = Query(10, ge=1, le=20),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Find attack paths using Breadth-First Search.
    
    BFS finds the shortest paths first, useful for identifying
    the quickest routes an attacker might take.
    """
    twin = get_twin_engine()
    
    paths = twin.find_attack_paths_bfs(
        start_id=start_id,
        target_id=target_id,
        max_depth=max_depth
    )
    
    logger.info(
        "BFS attack paths found",
        start=start_id,
        target=target_id,
        paths_count=len(paths)
    )
    
    return {
        "start": start_id,
        "target": target_id,
        "algorithm": "bfs",
        "paths_found": len(paths),
        "paths": paths[:50]  # Limit response size
    }


@router.get("/attack-paths/dfs")
async def find_attack_paths_dfs(
    start_id: str,
    target_id: str,
    max_depth: int = Query(10, ge=1, le=20),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Find attack paths using Depth-First Search.
    
    DFS explores all possible paths, useful for comprehensive
    attack surface analysis.
    """
    twin = get_twin_engine()
    
    paths = twin.find_attack_paths_dfs(
        start_id=start_id,
        target_id=target_id,
        max_depth=max_depth
    )
    
    logger.info(
        "DFS attack paths found",
        start=start_id,
        target=target_id,
        paths_count=len(paths)
    )
    
    return {
        "start": start_id,
        "target": target_id,
        "algorithm": "dfs",
        "paths_found": len(paths),
        "paths": paths[:50]  # Limit response size
    }


@router.post("/simulate/lateral-movement")
async def simulate_lateral_movement(
    initial_compromise: str,
    time_steps: int = Query(10, ge=1, le=100),
    propagation_probability: float = Query(0.3, ge=0.0, le=1.0),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Simulate lateral movement from an initial compromise.
    
    Uses a probabilistic model to simulate how an attacker
    might spread through the network over time.
    """
    twin = get_twin_engine()
    
    result = twin.simulate_lateral_movement(
        initial_compromise=initial_compromise,
        time_steps=time_steps,
        propagation_probability=propagation_probability
    )
    
    logger.info(
        "Lateral movement simulation complete",
        initial=initial_compromise,
        compromised=result.get("total_compromised", 0)
    )
    
    return result


@router.get("/blast-radius/{asset_id}")
async def calculate_blast_radius(
    asset_id: str,
    max_hops: int = Query(3, ge=1, le=10),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Calculate the blast radius of a compromised asset.
    
    Shows all assets that could be impacted within a certain
    number of network hops.
    """
    twin = get_twin_engine()
    
    result = twin.calculate_blast_radius(
        asset_id=asset_id,
        max_hops=max_hops
    )
    
    return result


@router.get("/critical-paths")
async def find_critical_paths(
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Find paths that lead to critical assets.
    
    Identifies attack paths from external-facing assets to
    critical internal systems.
    """
    twin = get_twin_engine()
    
    paths = twin.find_critical_paths()
    
    return {
        "critical_paths": paths,
        "total_paths": len(paths)
    }


@router.post("/simulate")
async def run_attack_simulation(
    attack_type: str = Query(..., description="Type of attack: ransomware, apt, insider, ddos"),
    entry_point: str = Query(..., description="Initial entry point asset ID"),
    target: Optional[str] = Query(None, description="Target asset ID (optional)"),
    current_user: Optional[TokenData] = Depends(get_current_user_optional)
):
    """
    Run a comprehensive attack simulation.
    
    Simulates an attack scenario from an entry point, analyzing
    possible attack paths, blast radius, and potential impact.
    Each attack type has different characteristics and impact patterns.
    """
    import uuid
    from collections import deque
    
    twin = get_twin_engine()
    
    # Initialize with sample network if empty
    if twin.graph.number_of_nodes() == 0:
        twin.initialize_sample_network()
    
    # Normalize attack type
    attack_type = attack_type.lower()
    
    # Get network stats for context
    stats = twin.get_network_stats()
    
    # Find critical paths from entry point
    paths_found = []
    blast_radius = []
    recommendations = []
    risk_assessment = "LOW"
    
    # Check if entry point exists, if not use a default
    if entry_point not in twin.graph:
        external_assets = [
            aid for aid, meta in twin.asset_metadata.items()
            if meta.get("zone") == "dmz" or meta.get("zone") == "external"
        ]
        if external_assets:
            entry_point = external_assets[0]
        elif twin.graph.nodes():
            entry_point = list(twin.graph.nodes())[0]
        else:
            return {
                "simulation_id": str(uuid.uuid4()),
                "attack_type": attack_type,
                "entry_point": entry_point,
                "target": target,
                "paths_found": [],
                "blast_radius": [],
                "risk_assessment": "UNKNOWN",
                "recommendations": ["No assets in network topology. Add assets first."]
            }
    
    # Attack type specific configuration
    attack_config = {
        "ransomware": {
            "max_hops": 3,
            "propagation_probability": 0.5,
            "priority_types": ["server", "database", "workstation"],
            "time_to_impact": "Hours",
            "primary_method": "Network propagation via SMB/shares",
        },
        "apt": {
            "max_hops": 6,
            "propagation_probability": 0.25,
            "priority_types": ["server", "network_device", "database"],
            "time_to_impact": "Days to Weeks",
            "primary_method": "Targeted lateral movement with persistence",
        },
        "insider": {
            "max_hops": 2,
            "propagation_probability": 0.0,  # Direct access, no spreading
            "priority_types": ["database", "server"],
            "time_to_impact": "Immediate",
            "primary_method": "Direct access to authorized resources",
        },
        "ddos": {
            "max_hops": 1,
            "propagation_probability": 0.0,  # No propagation, external attack
            "priority_types": ["firewall", "web_server", "network_device"],
            "time_to_impact": "Seconds to Minutes",
            "primary_method": "Overwhelming network bandwidth",
        }
    }
    
    config = attack_config.get(attack_type, attack_config["ransomware"])
    
    # Filter targets based on attack type
    if attack_type == "insider":
        # Insider threat targets data/databases
        critical_assets = [
            aid for aid, meta in twin.asset_metadata.items()
            if meta.get("asset_type") in ["database", "server"]
        ]
    elif attack_type == "ddos":
        # DDoS targets external-facing assets
        critical_assets = [
            aid for aid, meta in twin.asset_metadata.items()
            if meta.get("zone") in ["dmz", "external"]
        ]
    else:
        # Ransomware and APT target critical assets
        critical_assets = [
            aid for aid, meta in twin.asset_metadata.items()
            if meta.get("criticality") == "critical"
        ]
    
    # Calculate blast radius with attack-type-aware limiting
    blast_result = twin.calculate_blast_radius(entry_point, max_hops=config["max_hops"])
    
    # Extract affected assets from blast radius result
    if "critical_assets_at_risk" in blast_result:
        blast_radius.extend(blast_result.get("critical_assets_at_risk", []))
        blast_radius.extend(blast_result.get("high_assets_at_risk", []))
    
    # Use BFS to get reachable assets
    visited = {entry_point}
    queue = deque([entry_point])
    hop_count = 0
    
    while queue and hop_count < config["max_hops"]:
        level_size = len(queue)
        for _ in range(level_size):
            current = queue.popleft()
            for neighbor in twin.graph.neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    # For insider/ddos, limit blast radius
                    if attack_type in ["insider", "ddos"]:
                        if len(blast_radius) < 5:  # Limit to 5 assets
                            blast_radius.append(neighbor)
                    else:
                        blast_radius.append(neighbor)
                    if attack_type not in ["insider", "ddos"]:  # Propagating attacks
                        queue.append(neighbor)
        hop_count += 1
    
    # Find attack paths to critical assets or target
    targets_to_check = [target] if target else critical_assets[:5]
    
    for t in targets_to_check:
        if t and t != entry_point and t in twin.graph:
            found_paths = twin.find_attack_paths_bfs(entry_point, t, max_depth=config["max_hops"])
            # Limit paths per target based on attack type
            path_limit = 2 if attack_type == "insider" else 3
            for path in found_paths[:path_limit]:
                path_risk = len(path) * 2
                
                # Adjust risk scoring based on attack type
                if attack_type == "ransomware":
                    base_risk = 8.0  # Ransomware is highly damaging
                elif attack_type == "apt":
                    base_risk = 7.0  # APT is stealthy but effective
                elif attack_type == "insider":
                    base_risk = 9.0  # Insider threat bypasses defenses
                else:  # ddos
                    base_risk = 6.0  # DDoS is disruptive but limited scope
                
                risk_score = min(10, base_risk - len(path) * 0.5)
                
                paths_found.append({
                    "path": path,
                    "risk_score": risk_score,
                    "description": f"Attack path via {len(path)} hops - {config['primary_method']}",
                    "mitigations": get_attack_mitigations(attack_type, path)
                })
    
    # Simulate lateral movement (not applicable for insider/ddos)
    if attack_type not in ["insider", "ddos"]:
        sim_result = twin.simulate_lateral_movement(
            initial_compromise=entry_point,
            time_steps=10 if attack_type == "ransomware" else 5,
            propagation_probability=config["propagation_probability"]
        )
        compromised_count = sim_result.get("total_compromised", 0)
        critical_compromised = len(sim_result.get("critical_assets_compromised", []))
    else:
        # For insider/ddos, no lateral movement
        compromised_count = len(blast_radius)
        critical_compromised = len([a for a in blast_radius 
                                    if twin.asset_metadata.get(a, {}).get("criticality") == "critical"])
    
    # Calculate risk assessment based on attack type and impact
    if attack_type == "ransomware":
        if compromised_count > stats.get("total_nodes", 1) * 0.6:
            risk_assessment = "CRITICAL"
        elif compromised_count > stats.get("total_nodes", 1) * 0.3:
            risk_assessment = "HIGH"
        else:
            risk_assessment = "MEDIUM"
    elif attack_type == "apt":
        if critical_compromised > 2:
            risk_assessment = "CRITICAL"
        elif critical_compromised > 0:
            risk_assessment = "HIGH"
        else:
            risk_assessment = "MEDIUM"
    elif attack_type == "insider":
        risk_assessment = "CRITICAL"  # Insider threats are always critical
    else:  # ddos
        risk_assessment = "HIGH"  # DDoS impacts availability
    
    # Generate attack-specific recommendations
    recommendations = get_attack_recommendations(attack_type)
    
    logger.info(
        "Attack simulation complete",
        attack_type=attack_type,
        entry_point=entry_point,
        paths_found=len(paths_found),
        risk=risk_assessment,
        user_id=current_user.user_id
    )
    
    return {
        "simulation_id": str(uuid.uuid4()),
        "attack_type": attack_type,
        "entry_point": entry_point,
        "target": target,
        "paths_found": paths_found,
        "blast_radius": list(set(blast_radius)),
        "risk_assessment": risk_assessment,
        "recommendations": recommendations,
        "simulation_details": {
            "total_compromised": compromised_count,
            "critical_compromised": critical_compromised,
            "propagation_rate": config["propagation_probability"],
            "time_to_impact": config["time_to_impact"],
            "primary_method": config["primary_method"],
            "attack_scope": len(blast_radius)
        }
    }


def get_attack_mitigations(attack_type: str, path: List[str]) -> List[str]:
    """Generate attack-specific mitigations based on attack path."""
    if attack_type == "ransomware":
        return [
            "Maintain offline backups of data",
            f"Isolate {path[-1] if len(path) > 1 else path[0]} from network",
            "Disable macro execution in documents",
            "Restrict SMB v1 access"
        ]
    elif attack_type == "apt":
        return [
            f"Implement threat hunting for {path[0]}",
            "Deploy network segmentation between zones",
            "Enable enhanced logging and correlation",
            "Isolate compromised {path[-1] if len(path) > 1 else path[0]}"
        ]
    elif attack_type == "insider":
        return [
            "Implement data loss prevention (DLP)",
            f"Monitor access to {path[-1] if len(path) > 1 else path[0]}",
            "Apply principle of least privilege",
            "Conduct user behavior analytics"
        ]
    else:  # ddos
        return [
            "Deploy DDoS mitigation service",
            f"Rate limit traffic to {path[0]}",
            "Implement geo-blocking if applicable",
            "Scale infrastructure capacity"
        ]


def get_attack_recommendations(attack_type: str) -> List[str]:
    """Generate comprehensive recommendations based on attack type."""
    recommendations = {
        "ransomware": [
            "Maintain offline backups of critical data",
            "Disable SMB v1 and restrict lateral SMB access",
            "Implement network segmentation to limit lateral movement",
            "Deploy endpoint detection and response (EDR) solutions",
            "Enable immutable backups and retention policies",
            "Regular backup restoration testing"
        ],
        "apt": [
            "Implement advanced threat hunting procedures",
            "Deploy network traffic analysis tools",
            "Enable enhanced logging and SIEM correlation",
            "Restrict lateral movement with network segmentation",
            "Implement zero-trust access principles",
            "Conduct red team exercises regularly",
            "Use behavioral analytics to detect anomalies"
        ],
        "insider": [
            "Implement data loss prevention (DLP) controls",
            "Monitor privileged user activity continuously",
            "Apply principle of least privilege strictly",
            "Conduct user behavior analytics",
            "Implement multi-factor authentication",
            "Regular access reviews and recertification",
            "Separate duties for critical operations"
        ],
        "ddos": [
            "Deploy DDoS mitigation and filtering services",
            "Implement rate limiting on network edge",
            "Increase bandwidth capacity with redundancy",
            "Configure automatic traffic scrubbing",
            "Establish ISP-level DDoS protection contracts",
            "Test failover and redundancy regularly"
        ]
    }
    
    return recommendations.get(attack_type, recommendations["ransomware"])

