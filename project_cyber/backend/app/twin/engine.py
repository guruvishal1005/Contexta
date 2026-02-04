"""
Contexta Backend - Digital Twin Engine

Network topology simulation using NetworkX for attack path analysis
and lateral movement simulation.
"""

from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timezone
from collections import deque
import structlog
import networkx as nx
from uuid import UUID

logger = structlog.get_logger()


class DigitalTwinEngine:
    """
    Digital Twin Engine for network topology simulation.
    
    Uses NetworkX to model the organization's network infrastructure
    and simulate attack propagation scenarios.
    
    Features:
    - Network topology graph management
    - BFS/DFS attack path discovery
    - Lateral movement simulation
    - Blast radius calculation
    - Risk propagation modeling
    """
    
    def __init__(self):
        """Initialize the digital twin engine."""
        self.graph: nx.DiGraph = nx.DiGraph()
        self.asset_metadata: Dict[str, Dict[str, Any]] = {}
        self.vulnerability_data: Dict[str, List[Dict[str, Any]]] = {}
        
        logger.info("Digital twin engine initialized")
    
    def add_asset(
        self,
        asset_id: str,
        asset_type: str,
        name: str,
        criticality: str,
        zone: str = "internal",
        metadata: Dict[str, Any] = None
    ) -> None:
        """
        Add an asset to the digital twin graph.
        
        Args:
            asset_id: Unique asset identifier
            asset_type: Type of asset (server, workstation, network_device, etc.)
            name: Asset name
            criticality: Criticality level (critical, high, medium, low)
            zone: Network zone (dmz, internal, restricted, external)
            metadata: Additional asset metadata
        """
        self.graph.add_node(asset_id)
        
        self.asset_metadata[asset_id] = {
            "id": asset_id,
            "type": asset_type,
            "name": name,
            "criticality": criticality,
            "zone": zone,
            "compromised": False,
            "compromise_time": None,
            "metadata": metadata or {}
        }
        
        logger.debug("Asset added to digital twin", asset_id=asset_id, name=name)
    
    def add_connection(
        self,
        source_id: str,
        target_id: str,
        connection_type: str = "network",
        protocols: List[str] = None,
        weight: float = 1.0,
        bidirectional: bool = False
    ) -> None:
        """
        Add a connection between assets.
        
        Args:
            source_id: Source asset ID
            target_id: Target asset ID
            connection_type: Type of connection (network, trust, data_flow)
            protocols: Protocols allowed on this connection
            weight: Connection weight (lower = easier to traverse)
            bidirectional: Whether connection is bidirectional
        """
        edge_data = {
            "type": connection_type,
            "protocols": protocols or ["tcp"],
            "weight": weight
        }
        
        self.graph.add_edge(source_id, target_id, **edge_data)
        
        if bidirectional:
            self.graph.add_edge(target_id, source_id, **edge_data)
        
        logger.debug(
            "Connection added",
            source=source_id,
            target=target_id,
            type=connection_type
        )
    
    def add_vulnerability(
        self,
        asset_id: str,
        cve_id: str,
        cvss_score: float,
        exploitable: bool = False,
        network_exploitable: bool = False
    ) -> None:
        """
        Add a vulnerability to an asset.
        
        Args:
            asset_id: Asset ID
            cve_id: CVE identifier
            cvss_score: CVSS score
            exploitable: Whether exploit is available
            network_exploitable: Whether exploitable over network
        """
        if asset_id not in self.vulnerability_data:
            self.vulnerability_data[asset_id] = []
        
        self.vulnerability_data[asset_id].append({
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "exploitable": exploitable,
            "network_exploitable": network_exploitable
        })
    
    def find_attack_paths_bfs(
        self,
        start_id: str,
        target_id: str,
        max_depth: int = 10
    ) -> List[List[str]]:
        """
        Find attack paths using Breadth-First Search.
        
        BFS is optimal for finding shortest paths and is useful
        when we want to find the quickest routes an attacker might take.
        
        Args:
            start_id: Starting asset (compromised)
            target_id: Target asset (goal)
            max_depth: Maximum path depth
            
        Returns:
            List of paths (each path is a list of asset IDs)
        """
        if start_id not in self.graph or target_id not in self.graph:
            logger.warning(
                "Asset not found in graph",
                start=start_id,
                target=target_id
            )
            return []
        
        paths = []
        queue = deque([(start_id, [start_id])])
        visited_paths: Set[Tuple[str, ...]] = set()
        
        while queue:
            current, path = queue.popleft()
            
            if len(path) > max_depth:
                continue
            
            if current == target_id:
                paths.append(path)
                continue
            
            for neighbor in self.graph.neighbors(current):
                if neighbor not in path:  # Avoid cycles
                    new_path = path + [neighbor]
                    path_tuple = tuple(new_path)
                    
                    if path_tuple not in visited_paths:
                        visited_paths.add(path_tuple)
                        queue.append((neighbor, new_path))
        
        logger.info(
            "BFS attack paths found",
            start=start_id,
            target=target_id,
            paths_count=len(paths)
        )
        
        return paths
    
    def find_attack_paths_dfs(
        self,
        start_id: str,
        target_id: str,
        max_depth: int = 10
    ) -> List[List[str]]:
        """
        Find attack paths using Depth-First Search.
        
        DFS is useful for finding all possible paths and can be
        more memory efficient for deep searches.
        
        Args:
            start_id: Starting asset (compromised)
            target_id: Target asset (goal)
            max_depth: Maximum path depth
            
        Returns:
            List of paths (each path is a list of asset IDs)
        """
        if start_id not in self.graph or target_id not in self.graph:
            return []
        
        paths = []
        
        def dfs_recursive(current: str, path: List[str], visited: Set[str]):
            if len(path) > max_depth:
                return
            
            if current == target_id:
                paths.append(path.copy())
                return
            
            for neighbor in self.graph.neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    dfs_recursive(neighbor, path, visited)
                    path.pop()
                    visited.remove(neighbor)
        
        visited = {start_id}
        dfs_recursive(start_id, [start_id], visited)
        
        logger.info(
            "DFS attack paths found",
            start=start_id,
            target=target_id,
            paths_count=len(paths)
        )
        
        return paths
    
    def simulate_lateral_movement(
        self,
        initial_compromise: str,
        time_steps: int = 10,
        propagation_probability: float = 0.3
    ) -> Dict[str, Any]:
        """
        Simulate lateral movement from an initial compromise.
        
        Uses a probabilistic model to simulate how an attacker
        might spread through the network over time.
        
        Args:
            initial_compromise: Initially compromised asset
            time_steps: Number of simulation time steps
            propagation_probability: Base probability of spreading
            
        Returns:
            Simulation results including timeline and affected assets
        """
        import random
        
        if initial_compromise not in self.graph:
            return {"error": "Asset not found"}
        
        # Reset compromise state
        for asset_id in self.asset_metadata:
            self.asset_metadata[asset_id]["compromised"] = False
            self.asset_metadata[asset_id]["compromise_time"] = None
        
        # Initial compromise
        self.asset_metadata[initial_compromise]["compromised"] = True
        self.asset_metadata[initial_compromise]["compromise_time"] = 0
        
        compromised = {initial_compromise}
        timeline = [{
            "time_step": 0,
            "newly_compromised": [initial_compromise],
            "total_compromised": 1
        }]
        
        for t in range(1, time_steps + 1):
            newly_compromised = []
            
            for comp_asset in list(compromised):
                # Get all neighbors
                for neighbor in self.graph.neighbors(comp_asset):
                    if neighbor in compromised:
                        continue
                    
                    # Calculate propagation probability
                    prob = propagation_probability
                    
                    # Increase probability if target has vulnerabilities
                    if neighbor in self.vulnerability_data:
                        vulns = self.vulnerability_data[neighbor]
                        exploitable_vulns = [v for v in vulns if v["network_exploitable"]]
                        if exploitable_vulns:
                            # Higher probability for exploitable vulns
                            max_cvss = max(v["cvss_score"] for v in exploitable_vulns)
                            prob += (max_cvss / 10) * 0.3
                    
                    # Attempt propagation
                    if random.random() < prob:
                        compromised.add(neighbor)
                        newly_compromised.append(neighbor)
                        self.asset_metadata[neighbor]["compromised"] = True
                        self.asset_metadata[neighbor]["compromise_time"] = t
            
            timeline.append({
                "time_step": t,
                "newly_compromised": newly_compromised,
                "total_compromised": len(compromised)
            })
        
        # Calculate statistics
        critical_assets_compromised = [
            aid for aid in compromised
            if self.asset_metadata[aid]["criticality"] == "critical"
        ]
        
        high_assets_compromised = [
            aid for aid in compromised
            if self.asset_metadata[aid]["criticality"] == "high"
        ]
        
        logger.info(
            "Lateral movement simulation complete",
            initial=initial_compromise,
            total_compromised=len(compromised),
            critical_compromised=len(critical_assets_compromised)
        )
        
        return {
            "initial_compromise": initial_compromise,
            "simulation_steps": time_steps,
            "total_compromised": len(compromised),
            "compromised_assets": list(compromised),
            "critical_assets_compromised": critical_assets_compromised,
            "high_assets_compromised": high_assets_compromised,
            "timeline": timeline,
            "propagation_rate": len(compromised) / time_steps if time_steps > 0 else 0
        }
    
    def calculate_blast_radius(
        self,
        asset_id: str,
        max_hops: int = 3
    ) -> Dict[str, Any]:
        """
        Calculate the blast radius of a compromised asset.
        
        The blast radius represents all assets that could be
        directly impacted within a certain number of network hops.
        
        Args:
            asset_id: The asset to analyze
            max_hops: Maximum number of hops to consider
            
        Returns:
            Blast radius analysis
        """
        if asset_id not in self.graph:
            return {"error": "Asset not found"}
        
        # Use BFS to find all reachable assets within max_hops
        reachable_by_hop: Dict[int, List[str]] = {0: [asset_id]}
        visited = {asset_id}
        current_level = [asset_id]
        
        for hop in range(1, max_hops + 1):
            next_level = []
            
            for current in current_level:
                for neighbor in self.graph.neighbors(current):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        next_level.append(neighbor)
            
            reachable_by_hop[hop] = next_level
            current_level = next_level
        
        # Calculate risk scores
        total_risk = 0
        risk_by_hop = {}
        
        criticality_weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1
        }
        
        for hop, assets in reachable_by_hop.items():
            hop_risk = 0
            for aid in assets:
                crit = self.asset_metadata.get(aid, {}).get("criticality", "medium")
                hop_risk += criticality_weights.get(crit, 4)
            
            # Apply distance decay
            decay_factor = 1 / (hop + 1)
            hop_risk *= decay_factor
            risk_by_hop[hop] = round(hop_risk, 2)
            total_risk += hop_risk
        
        # Get unique affected assets
        all_affected = []
        for hop in range(1, max_hops + 1):
            all_affected.extend(reachable_by_hop.get(hop, []))
        
        # Categorize by criticality
        affected_by_criticality = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for aid in all_affected:
            crit = self.asset_metadata.get(aid, {}).get("criticality", "medium")
            affected_by_criticality[crit].append(aid)
        
        logger.info(
            "Blast radius calculated",
            asset_id=asset_id,
            total_affected=len(all_affected),
            total_risk=round(total_risk, 2)
        )
        
        return {
            "source_asset": asset_id,
            "max_hops_analyzed": max_hops,
            "total_affected_assets": len(all_affected),
            "affected_by_hop": {k: len(v) for k, v in reachable_by_hop.items() if k > 0},
            "affected_by_criticality": {k: len(v) for k, v in affected_by_criticality.items()},
            "risk_score": round(total_risk, 2),
            "risk_by_hop": risk_by_hop,
            "critical_assets_at_risk": affected_by_criticality["critical"],
            "high_assets_at_risk": affected_by_criticality["high"]
        }
    
    def find_critical_paths(self) -> List[Dict[str, Any]]:
        """
        Find paths that lead to critical assets.
        
        Identifies all paths from external/DMZ assets to
        critical internal assets.
        
        Returns:
            List of critical attack paths with risk scores
        """
        # Find entry points (DMZ, external facing)
        entry_points = [
            aid for aid, meta in self.asset_metadata.items()
            if meta.get("zone") in ["dmz", "external"]
        ]
        
        # Find critical targets
        critical_targets = [
            aid for aid, meta in self.asset_metadata.items()
            if meta.get("criticality") == "critical"
        ]
        
        critical_paths = []
        
        for entry in entry_points:
            for target in critical_targets:
                paths = self.find_attack_paths_bfs(entry, target, max_depth=8)
                
                for path in paths:
                    # Calculate path risk
                    risk = self._calculate_path_risk(path)
                    
                    critical_paths.append({
                        "entry_point": entry,
                        "target": target,
                        "path": path,
                        "path_length": len(path),
                        "risk_score": risk
                    })
        
        # Sort by risk (highest first)
        critical_paths.sort(key=lambda x: x["risk_score"], reverse=True)
        
        logger.info(
            "Critical paths identified",
            total_paths=len(critical_paths)
        )
        
        return critical_paths[:20]  # Top 20 paths
    
    def _calculate_path_risk(self, path: List[str]) -> float:
        """
        Calculate risk score for an attack path.
        
        Considers:
        - Path length (shorter = higher risk)
        - Vulnerabilities along the path
        - Asset criticality
        """
        if not path:
            return 0
        
        base_risk = 10 / len(path)  # Shorter paths = higher risk
        
        vuln_bonus = 0
        for asset_id in path:
            if asset_id in self.vulnerability_data:
                for vuln in self.vulnerability_data[asset_id]:
                    if vuln["network_exploitable"]:
                        vuln_bonus += vuln["cvss_score"] * 0.1
        
        # Add criticality of final target
        final_asset = self.asset_metadata.get(path[-1], {})
        criticality_bonus = {
            "critical": 5,
            "high": 3,
            "medium": 1,
            "low": 0
        }.get(final_asset.get("criticality", "medium"), 1)
        
        return round(base_risk + vuln_bonus + criticality_bonus, 2)
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get statistics about the digital twin network."""
        return {
            "total_assets": self.graph.number_of_nodes(),
            "total_connections": self.graph.number_of_edges(),
            "assets_with_vulnerabilities": len(self.vulnerability_data),
            "total_vulnerabilities": sum(
                len(v) for v in self.vulnerability_data.values()
            ),
            "assets_by_zone": self._count_by_attribute("zone"),
            "assets_by_criticality": self._count_by_attribute("criticality"),
            "assets_by_type": self._count_by_attribute("type"),
            "graph_density": nx.density(self.graph) if self.graph.number_of_nodes() > 0 else 0,
            "is_connected": nx.is_weakly_connected(self.graph) if self.graph.number_of_nodes() > 0 else False
        }
    
    def _count_by_attribute(self, attribute: str) -> Dict[str, int]:
        """Count assets by a given attribute."""
        counts: Dict[str, int] = {}
        for meta in self.asset_metadata.values():
            value = meta.get(attribute, "unknown")
            counts[value] = counts.get(value, 0) + 1
        return counts
    
    def export_to_dict(self) -> Dict[str, Any]:
        """Export the digital twin to a dictionary format."""
        return {
            "nodes": [
                {
                    "id": node,
                    **self.asset_metadata.get(node, {})
                }
                for node in self.graph.nodes()
            ],
            "edges": [
                {
                    "source": u,
                    "target": v,
                    **data
                }
                for u, v, data in self.graph.edges(data=True)
            ],
            "vulnerabilities": self.vulnerability_data,
            "stats": self.get_network_stats()
        }
    
    def import_from_dict(self, data: Dict[str, Any]) -> None:
        """Import digital twin from a dictionary format."""
        # Clear existing data
        self.graph.clear()
        self.asset_metadata.clear()
        self.vulnerability_data.clear()
        
        # Import nodes
        for node in data.get("nodes", []):
            node_id = node.pop("id")
            self.add_asset(
                asset_id=node_id,
                asset_type=node.get("type", "unknown"),
                name=node.get("name", node_id),
                criticality=node.get("criticality", "medium"),
                zone=node.get("zone", "internal"),
                metadata=node.get("metadata", {})
            )
        
        # Import edges
        for edge in data.get("edges", []):
            self.add_connection(
                source_id=edge["source"],
                target_id=edge["target"],
                connection_type=edge.get("type", "network"),
                protocols=edge.get("protocols", ["tcp"]),
                weight=edge.get("weight", 1.0)
            )
        
        # Import vulnerabilities
        self.vulnerability_data = data.get("vulnerabilities", {})
        
        logger.info(
            "Digital twin imported",
            nodes=self.graph.number_of_nodes(),
            edges=self.graph.number_of_edges()
        )
    
    def initialize_sample_network(self) -> None:
        """
        Initialize a sample network topology for demonstration.
        
        Creates a realistic enterprise network with DMZ, internal,
        and restricted zones including common assets and connections.
        """
        # DMZ Assets
        self.add_asset("external_firewall", "firewall", "External Firewall", "critical", "dmz")
        self.add_asset("web_server_1", "server", "Public Web Server 1", "high", "dmz")
        self.add_asset("web_server_2", "server", "Public Web Server 2", "high", "dmz")
        self.add_asset("mail_gateway", "server", "Mail Gateway", "high", "dmz")
        self.add_asset("vpn_gateway", "network_device", "VPN Gateway", "critical", "dmz")
        
        # Internal Assets
        self.add_asset("internal_firewall", "firewall", "Internal Firewall", "critical", "internal")
        self.add_asset("ad_server", "server", "Active Directory Server", "critical", "internal")
        self.add_asset("file_server", "server", "File Server", "high", "internal")
        self.add_asset("app_server_1", "server", "Application Server 1", "high", "internal")
        self.add_asset("app_server_2", "server", "Application Server 2", "medium", "internal")
        self.add_asset("workstation_1", "workstation", "Finance Workstation", "medium", "internal")
        self.add_asset("workstation_2", "workstation", "HR Workstation", "medium", "internal")
        self.add_asset("workstation_3", "workstation", "IT Admin Workstation", "high", "internal")
        self.add_asset("printer_1", "iot", "Network Printer", "low", "internal")
        
        # Restricted Zone (Data Center)
        self.add_asset("db_server_1", "database", "Production Database", "critical", "restricted")
        self.add_asset("db_server_2", "database", "Backup Database", "high", "restricted")
        self.add_asset("scada_controller", "ics", "SCADA Controller", "critical", "restricted")
        self.add_asset("backup_server", "server", "Backup Server", "high", "restricted")
        
        # DMZ Connections
        self.add_connection("external_firewall", "web_server_1", "network", ["https", "http"])
        self.add_connection("external_firewall", "web_server_2", "network", ["https", "http"])
        self.add_connection("external_firewall", "mail_gateway", "network", ["smtp", "imaps"])
        self.add_connection("external_firewall", "vpn_gateway", "network", ["ipsec"])
        self.add_connection("external_firewall", "internal_firewall", "network", ["tcp"])
        
        # DMZ to Internal
        self.add_connection("web_server_1", "internal_firewall", "network", ["tcp"])
        self.add_connection("web_server_2", "internal_firewall", "network", ["tcp"])
        self.add_connection("mail_gateway", "internal_firewall", "network", ["smtp"])
        self.add_connection("vpn_gateway", "internal_firewall", "network", ["tcp"])
        
        # Internal Network Connections
        self.add_connection("internal_firewall", "ad_server", "network", ["ldap", "kerberos"], bidirectional=True)
        self.add_connection("internal_firewall", "file_server", "network", ["smb"], bidirectional=True)
        self.add_connection("internal_firewall", "app_server_1", "network", ["tcp"], bidirectional=True)
        self.add_connection("internal_firewall", "app_server_2", "network", ["tcp"], bidirectional=True)
        
        self.add_connection("ad_server", "file_server", "trust", ["ldap"], bidirectional=True)
        self.add_connection("ad_server", "app_server_1", "trust", ["ldap"], bidirectional=True)
        self.add_connection("ad_server", "app_server_2", "trust", ["ldap"], bidirectional=True)
        self.add_connection("ad_server", "workstation_1", "trust", ["ldap"], bidirectional=True)
        self.add_connection("ad_server", "workstation_2", "trust", ["ldap"], bidirectional=True)
        self.add_connection("ad_server", "workstation_3", "trust", ["ldap"], bidirectional=True)
        
        self.add_connection("file_server", "workstation_1", "data_flow", ["smb"], bidirectional=True)
        self.add_connection("file_server", "workstation_2", "data_flow", ["smb"], bidirectional=True)
        self.add_connection("file_server", "workstation_3", "data_flow", ["smb"], bidirectional=True)
        
        self.add_connection("app_server_1", "db_server_1", "data_flow", ["sql"])
        self.add_connection("app_server_2", "db_server_1", "data_flow", ["sql"])
        
        self.add_connection("workstation_3", "app_server_1", "network", ["ssh"])
        self.add_connection("workstation_3", "app_server_2", "network", ["ssh"])
        self.add_connection("workstation_3", "db_server_1", "network", ["ssh"])
        self.add_connection("workstation_3", "scada_controller", "network", ["modbus"])
        
        # Restricted Zone Connections
        self.add_connection("db_server_1", "db_server_2", "data_flow", ["sql"], bidirectional=True)
        self.add_connection("db_server_1", "backup_server", "data_flow", ["tcp"])
        self.add_connection("db_server_2", "backup_server", "data_flow", ["tcp"])
        
        # Printer on internal network
        self.add_connection("printer_1", "workstation_1", "network", ["ipp"], bidirectional=True)
        self.add_connection("printer_1", "workstation_2", "network", ["ipp"], bidirectional=True)
        
        # Add some sample vulnerabilities
        self.add_vulnerability("web_server_1", "CVE-2024-1234", 8.5, True, True)
        self.add_vulnerability("web_server_2", "CVE-2024-1234", 8.5, True, True)
        self.add_vulnerability("app_server_1", "CVE-2024-5678", 7.2, True, True)
        self.add_vulnerability("file_server", "CVE-2024-9012", 6.5, False, True)
        self.add_vulnerability("printer_1", "CVE-2024-3456", 5.0, True, False)
        self.add_vulnerability("scada_controller", "CVE-2024-7890", 9.8, True, True)
        
        logger.info(
            "Sample network initialized",
            nodes=self.graph.number_of_nodes(),
            edges=self.graph.number_of_edges()
        )


# Singleton instance
_twin_engine: Optional[DigitalTwinEngine] = None


def get_twin_engine() -> DigitalTwinEngine:
    """Get or create the digital twin engine singleton."""
    global _twin_engine
    if _twin_engine is None:
        _twin_engine = DigitalTwinEngine()
    return _twin_engine
