# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
Route Table Analyzer for AKS Network Diagnostics

This module analyzes User Defined Routes (UDRs) and Route Tables associated with AKS node subnets.
It identifies potential connectivity issues, categorizes routes by impact, and detects common
misconfigurations that could affect AKS cluster operations.

Key Features:
- Analyzes route tables associated with AKS node subnets
- Assesses route impact on AKS connectivity (critical, high, medium, low)
- Categorizes routes by type (default routes, virtual appliance, Azure services, etc.)
- Detects common issues like blackhole routes, Azure service blocking, MCR access issues
- Supports multiple agent pools with different subnet configurations

Adapted for Azure CLI - uses pre-authenticated SDK clients.
"""

from typing import Any, Dict, List, Optional, Set

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError


def _to_dict(obj: Any) -> Any:
    """Convert Azure SDK object to dictionary"""
    if hasattr(obj, 'as_dict'):
        return obj.as_dict()
    return obj


class RouteTableAnalyzer:  # pylint: disable=too-few-public-methods
    """
    Analyzes User Defined Routes (UDRs) and Route Tables for AKS clusters.

    This class examines route tables associated with AKS node subnets to identify
    potential connectivity issues and assess the impact of routes on cluster operations.
    """

    def __init__(self, agent_pools: List[Dict[str, Any]], network_client=None,
                 vmss_analysis: List[Dict[str, Any]] = None, logger=None):
        """
        Initialize the RouteTableAnalyzer.

        Args:
            agent_pools: List of AKS agent pool configurations
            network_client: Authenticated NetworkManagementClient (can be dict for backward compatibility)
            vmss_analysis: Optional list of VMSS network configurations (for managed VNets)
            logger: Optional logger instance
        """
        self.agent_pools = agent_pools
        self.vmss_analysis = vmss_analysis or []

        # Handle backward compatibility: network_client might be a dict of clients
        if isinstance(network_client, dict):
            self.network_client = network_client.get('network_client')
        else:
            self.network_client = network_client

        self.logger = logger or __import__('logging').getLogger(__name__)

    def analyze(self) -> Dict[str, Any]:
        """
        Analyze User Defined Routes on node subnets.

        Returns:
            Dictionary containing route table analysis results with structure:
            {
                "route_tables": [...],           # List of analyzed route tables
                "critical_routes": [...],        # Routes with critical/high impact
                "virtual_appliance_routes": [...],# Routes through virtual appliances
                "internet_routes": [...]         # Internet-bound routes
            }
        """
        self.logger.info("    Analyzing UDRs on node subnets...")

        udr_analysis = {
            "route_tables": [],
            "critical_routes": [],
            "virtual_appliance_routes": [],
            "internet_routes": []
        }

        # Get unique subnet IDs from agent pools
        subnet_ids = self._get_unique_subnet_ids()

        if not subnet_ids:
            self.logger.info("    No VNet-integrated node pools found")
            return udr_analysis

        # Analyze each subnet for route tables
        for subnet_id in subnet_ids:
            try:
                subnet_info = self._get_subnet_details(subnet_id)
                if not subnet_info:
                    continue

                route_table = subnet_info.get("route_table")
                if route_table and route_table.get("id"):
                    route_table_id = route_table["id"]
                    route_table_name = route_table_id.split("/")[-1] if route_table_id else "unknown"
                    self.logger.warning("  Found route table: %s", route_table_name)

                    # Get route table details
                    rt_analysis = self._analyze_route_table(route_table_id, subnet_id)
                    if rt_analysis:
                        udr_analysis["route_tables"].append(rt_analysis)

                        # Categorize routes
                        for route in rt_analysis.get("routes", []):
                            self._categorize_route(route, udr_analysis)
                else:
                    self.logger.info("    No route table associated with subnet: %s", subnet_id)

            except Exception as e:  # pylint: disable=broad-except
                self.logger.info("    Error analyzing subnet %s: %s", subnet_id, e)

        return udr_analysis

    def _get_unique_subnet_ids(self) -> Set[str]:
        """
        Extract unique subnet IDs from agent pools and VMSS network profiles.

        For clusters with custom VNets, subnet IDs are available in agent pool configurations.
        For clusters with AKS-managed VNets, subnet IDs are only available in VMSS network profiles.
        This method supports both scenarios.
        """
        subnet_ids = set()

        # Try to get subnet IDs from agent pools (customer-provided VNets)
        for pool in self.agent_pools:
            # Try both camelCase and snake_case
            subnet_id = pool.get("vnetSubnetId") or pool.get("vnet_subnet_id")
            if subnet_id and subnet_id != "null":
                subnet_ids.add(subnet_id)
                self.logger.info("    Found subnet from agent pool: %s", subnet_id)

        # If no subnets found in agent pools, extract from VMSS (AKS-managed VNets)
        if not subnet_ids and self.vmss_analysis:
            self.logger.info("    No subnets in agent pools, checking VMSS network configuration...")
            subnet_ids = self._extract_subnet_ids_from_vmss()

        return subnet_ids

    def _extract_subnet_ids_from_vmss(self) -> Set[str]:
        """
        Extract subnet IDs from VMSS network configuration.

        Returns:
            Set of subnet resource IDs
        """
        subnet_ids = set()

        for vmss in self.vmss_analysis:
            # Handle case where vmss might not be a dict
            if not isinstance(vmss, dict):
                self.logger.warning("    Unexpected VMSS data type: %s", type(vmss))
                continue

            # Extract subnet ID from VMSS network profile
            # Path: virtual_machine_profile.network_profile.
            # network_interface_configurations[].ip_configurations[].subnet.id
            vm_profile = vmss.get("virtual_machine_profile", {})
            network_profile = vm_profile.get("network_profile", {})
            nic_configs = network_profile.get("network_interface_configurations", [])

            for nic_config in nic_configs:
                ip_configs = nic_config.get("ip_configurations", [])
                for ip_config in ip_configs:
                    subnet = ip_config.get("subnet", {})
                    subnet_id = subnet.get("id")
                    if subnet_id:
                        subnet_ids.add(subnet_id)
                        # Log only once per unique subnet
                        if len(subnet_ids) == 1 or subnet_id not in subnet_ids:
                            self.logger.info("    Found subnet from VMSS network profile: %s", subnet_id)
                        break  # Only need one IP config per NIC
                if subnet_ids:
                    break  # Only need one NIC

        return subnet_ids

    def _get_subnet_details(self, subnet_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a subnet.

        Args:
            subnet_id: Azure resource ID of the subnet

        Returns:
            Subnet details dictionary or None if error occurs
        """
        try:
            # Parse subnet ID manually
            # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}  # pylint: disable=line-too-long
            parts = subnet_id.split("/")
            if len(parts) < 11:
                self.logger.info("    Invalid subnet ID format: %s", subnet_id)
                return None

            resource_group = parts[4]
            vnet_name = parts[8]
            subnet_name = parts[10]

            # Get subnet details
            subnet = self.network_client.subnets.get(resource_group, vnet_name, subnet_name)
            return _to_dict(subnet)

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.info("    Error getting subnet details for %s: %s", subnet_id, e)
            return None
        except Exception as e:  # pylint: disable=broad-except
            self.logger.info("    Error parsing subnet ID %s: %s", subnet_id, e)
            return None

    def _analyze_route_table(
        self, route_table_id: str, subnet_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze a specific route table.

        Args:
            route_table_id: Azure resource ID of the route table
            subnet_id: Azure resource ID of the associated subnet

        Returns:
            Route table analysis dictionary or None if error occurs
        """
        try:
            # Parse route table ID
            # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/routeTables/{rt}
            parts = route_table_id.split("/")
            if len(parts) < 9:
                return None

            resource_group = parts[4]
            route_table_name = parts[8]

            # Get route table details
            route_table = self.network_client.route_tables.get(resource_group, route_table_name)
            route_table_info = _to_dict(route_table)

            if not route_table_info:
                return None

            analysis = {
                "id": route_table_id,
                "name": route_table_name,
                "resource_group": resource_group,
                "associated_subnet": subnet_id,
                "routes": [],
                "disable_bgp_route_propagation": route_table_info.get(
                    "disable_bgp_route_propagation", False
                ),
            }

            # Analyze each route
            routes = route_table_info.get("routes", [])
            for route in routes:
                route_analysis = self._analyze_individual_route(route)
                if route_analysis:
                    analysis["routes"].append(route_analysis)

            self.logger.info("    Route table %s has %s route(s)", route_table_name, len(routes))

            return analysis

        except Exception as e:  # pylint: disable=broad-except
            self.logger.info("    Error analyzing route table %s: %s", route_table_id, e)
            return None

    def _analyze_individual_route(self, route: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze an individual route"""
        try:
            next_hop_type = route.get("next_hop_type", "")
            address_prefix = route.get("address_prefix", "")
            next_hop_ip = route.get("next_hop_ip_address", "")
            route_name = route.get("name", "")

            analysis = {
                "name": route_name,
                "address_prefix": address_prefix,
                "next_hop_type": next_hop_type,
                "next_hop_ip_address": next_hop_ip,
                "provisioning_state": route.get("provisioning_state", ""),
                "impact": self._assess_route_impact(address_prefix, next_hop_type, next_hop_ip),
            }

            return analysis

        except Exception as e:  # pylint: disable=broad-except
            self.logger.info("    Error analyzing route: %s", e)
            return None

    def _assess_route_impact(
        self, address_prefix: str, next_hop_type: str, _next_hop_ip: str
    ) -> Dict[str, Any]:
        """Assess the potential impact of a route on AKS connectivity"""
        impact = {"severity": "info", "description": "", "affected_traffic": []}

        # Check for default route (0.0.0.0/0)
        if address_prefix == "0.0.0.0/0":
            if next_hop_type == "VirtualAppliance":
                impact["severity"] = "high"
                impact["description"] = "Default route redirects ALL internet traffic to virtual appliance"
                impact["affected_traffic"] = [
                    "internet", "container_registry", "azure_services", "api_server"
                ]
            elif next_hop_type == "None":
                impact["severity"] = "critical"
                impact["description"] = "Default route drops ALL internet traffic (blackhole)"
                impact["affected_traffic"] = [
                    "internet", "container_registry", "azure_services", "api_server"
                ]
            elif next_hop_type == "Internet":
                impact["severity"] = "low"
                impact["description"] = "Explicit default route to internet (may override system routes)"
                impact["affected_traffic"] = ["internet"]

        # Check for container registry routes BEFORE Azure services
        elif self._is_container_registry_prefix(address_prefix):
            if next_hop_type == "VirtualAppliance":
                impact["severity"] = "medium"
                impact["description"] = (
                    f"Container registry traffic ({address_prefix}) redirected to virtual appliance"
                )
                impact["affected_traffic"] = ["container_registry"]
            elif next_hop_type == "None":
                impact["severity"] = "high"
                impact["description"] = f"Container registry traffic ({address_prefix}) blocked"
                impact["affected_traffic"] = ["container_registry"]

        # Check for Azure service routes
        elif self._is_azure_service_prefix(address_prefix):
            if next_hop_type == "VirtualAppliance":
                impact["severity"] = "medium"
                impact["description"] = (
                    f"Azure service traffic ({address_prefix}) redirected to virtual appliance"
                )
                impact["affected_traffic"] = ["azure_services"]
            elif next_hop_type == "None":
                impact["severity"] = "high"
                impact["description"] = f"Azure service traffic ({address_prefix}) blocked"
                impact["affected_traffic"] = ["azure_services"]

        # Check for private network routes
        elif self._is_private_network_prefix(address_prefix):
            if next_hop_type == "VirtualAppliance":
                impact["severity"] = "low"
                impact["description"] = (
                    f"Private network traffic ({address_prefix}) redirected to virtual appliance"
                )
                impact["affected_traffic"] = ["private_network"]

        return impact

    def _is_azure_service_prefix(self, address_prefix: str) -> bool:
        """Check if address prefix covers Azure service endpoints"""
        azure_prefixes = ["13.", "20.", "23.", "40.", "52.", "104.", "168.", "191."]
        return any(address_prefix.startswith(prefix) for prefix in azure_prefixes)

    def _is_container_registry_prefix(self, address_prefix: str) -> bool:
        """Check if address prefix covers container registry endpoints"""
        mcr_prefixes = ["20.81.", "20.117.", "52.159.", "52.168."]
        return any(address_prefix.startswith(prefix) for prefix in mcr_prefixes)

    def _is_private_network_prefix(self, address_prefix: str) -> bool:
        """Check if address prefix is for private networks (RFC 1918)"""
        private_prefixes = [
            "10.",
            "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
            "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168.",
        ]
        return any(address_prefix.startswith(prefix) for prefix in private_prefixes)

    def _categorize_route(self, route: Dict[str, Any], udr_analysis: Dict[str, Any]) -> None:
        """Categorize routes based on their impact"""
        impact = route.get("impact", {})
        severity = impact.get("severity", "info")
        next_hop_type = route.get("next_hop_type", "")
        address_prefix = route.get("address_prefix", "")

        # Critical routes (high impact on connectivity)
        if severity in ["critical", "high"]:
            udr_analysis["critical_routes"].append(
                {
                    "name": route.get("name", ""),
                    "address_prefix": address_prefix,
                    "next_hop_type": next_hop_type,
                    "impact": impact,
                }
            )

        # Virtual appliance routes
        if next_hop_type == "VirtualAppliance":
            udr_analysis["virtual_appliance_routes"].append(
                {
                    "name": route.get("name", ""),
                    "address_prefix": address_prefix,
                    "next_hop_ip_address": route.get("next_hop_ip_address", ""),
                    "impact": impact,
                }
            )

        # Internet routes
        if address_prefix == "0.0.0.0/0" or next_hop_type == "Internet":
            udr_analysis["internet_routes"].append(
                {
                    "name": route.get("name", ""),
                    "address_prefix": address_prefix,
                    "next_hop_type": next_hop_type,
                    "impact": impact,
                }
            )
