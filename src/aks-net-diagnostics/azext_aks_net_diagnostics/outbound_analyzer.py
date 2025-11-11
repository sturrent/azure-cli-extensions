"""
Outbound Connectivity Analyzer for AKS clusters

This module analyzes outbound connectivity mechanisms including:
- Load Balancer outbound configuration
- NAT Gateway configuration
- User Defined Routing (UDR) with virtual appliances
- Effective outbound path determination with UDR override detection

Adapted for Azure CLI integration.
"""

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-instance-attributes,too-many-nested-blocks

import logging
import re
from typing import Any, Dict, List, Optional, Set

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

from .models import Finding, FindingCode, Severity


class OutboundConnectivityAnalyzer:
    """Analyzer for AKS cluster outbound connectivity configuration"""

    def __init__(
        self,
        cluster_info: Dict[str, Any],
        agent_pools: List[Dict[str, Any]],
        clients: Dict[str, Any],
        route_table_analysis: Optional[Dict[str, Any]] = None,
        vmss_info: Optional[List[Dict[str, Any]]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize the OutboundConnectivityAnalyzer

        Args:
            cluster_info: AKS cluster configuration dictionary
            agent_pools: List of agent pool configurations
            clients: Dictionary containing Azure SDK clients
                - network_client: NetworkManagementClient instance
                - subscription_id: Current subscription ID
                - credential: Azure credentials
            route_table_analysis: Pre-computed route table analysis results (optional)
            vmss_info: VMSS configuration data from cluster (optional)
            logger: Optional logger instance
        """
        self.cluster_info = cluster_info
        self.agent_pools = agent_pools
        self.network_client = clients["network_client"]
        self.subscription_id = clients["subscription_id"]
        self.credential = clients["credential"]
        self.route_table_analysis = route_table_analysis or {}
        self.vmss_info = vmss_info or []
        self.logger = logger or logging.getLogger(__name__)

        # Results storage
        self.outbound_ips: List[str] = []
        self.outbound_analysis: Dict[str, Any] = {}
        self.findings: List[Finding] = []

    def _check_authorization_error(
        self,
        error: HttpResponseError,
        resource_type: str,
        resource_group: str
    ) -> bool:
        """
        Check if the error is an authorization failure and create a finding.

        Args:
            error: The HttpResponseError to check
            resource_type: Type of resource (e.g., 'LoadBalancer')
            resource_group: Resource group name

        Returns:
            True if this was an authorization error, False otherwise
        """
        error_message = str(error.message) if hasattr(error, 'message') else str(error)

        if 'AuthorizationFailed' in error_message or 'authorization failed' in error_message.lower():
            # Extract permission from error message if available
            permission_match = re.search(
                r"Microsoft\.\w+/[\w/]+/\w+",
                error_message
            )
            missing_permission = permission_match.group(0) if permission_match else "Unknown permission"

            # Build recommendation message
            recommendation = (
                f"Grant the 'Reader' role on resource group '{resource_group}' or assign a role with the "
                f"'{missing_permission}' permission to access {resource_type} resources. "
                f"Use: az role assignment create --role Reader --assignee <principal-id> "
                f"--scope /subscriptions/<subscription-id>/resourceGroups/{resource_group}"
            )

            # Create finding
            finding = Finding(
                severity=Severity.WARNING,
                code=FindingCode.PERMISSION_INSUFFICIENT_LB,
                message=f"Incomplete {resource_type} Analysis - Missing permission to read {resource_group}",
                recommendation=recommendation,
                details={
                    'resource_type': resource_type,
                    'resource_group': resource_group,
                    'missing_permission': missing_permission,
                    'error': error_message
                }
            )
            self.findings.append(finding)
            self.logger.warning("  %s", finding.message)
            return True

        return False

    def analyze(self, show_details: bool = False) -> Dict[str, Any]:
        """
        Analyze outbound connectivity configuration

        Args:
            show_details: Enable detailed logging

        Returns:
            Dictionary containing outbound connectivity analysis results
        """
        self.logger.info("Analyzing outbound connectivity...")

        network_profile = self.cluster_info.get("network_profile", {})
        outbound_type = network_profile.get("outbound_type", "loadBalancer")

        # Analyze based on configured outbound type
        if outbound_type == "loadBalancer":
            self._analyze_load_balancer_outbound(show_details)
        elif outbound_type == "userDefinedRouting":
            self._analyze_udr_outbound()
        elif outbound_type in ("managedNATGateway", "userAssignedNATGateway"):
            self._analyze_nat_gateway_outbound(show_details, outbound_type)

        # Use pre-computed route table analysis from Phase 3
        # (no need to re-analyze - it's already been done)
        udr_analysis = self.route_table_analysis

        # Determine effective outbound configuration and warn about conflicts
        effective_outbound_summary = self._determine_effective_outbound(
            outbound_type, udr_analysis
        )

        self.outbound_analysis = {
            "type": outbound_type,
            "configured_public_ips": self.outbound_ips.copy(),
            "effective_outbound": effective_outbound_summary,
            "udr_analysis": udr_analysis if udr_analysis.get("route_tables") else None,
        }

        # Display summary of effective outbound configuration
        self._display_outbound_summary(effective_outbound_summary)

        return self.outbound_analysis

    def get_outbound_ips(self) -> List[str]:
        """Get list of configured outbound public IPs"""
        return self.outbound_ips.copy()

    def _determine_effective_outbound(
        self, outbound_type: str, udr_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Determine the effective outbound configuration considering UDRs

        Args:
            outbound_type: Configured outbound type from cluster
            udr_analysis: UDR analysis results

        Returns:
            Dictionary with effective outbound configuration details
        """
        effective_summary = {
            "mechanism": outbound_type,
            "overridden_by_udr": False,
            "effective_mechanism": outbound_type,
            "virtual_appliance_ips": [],
            "load_balancer_ips": self.outbound_ips.copy(),
            "warnings": [],
            "description": "",
        }

        # Check if UDRs override the configured outbound type
        virtual_appliance_routes = udr_analysis.get("virtual_appliance_routes", [])

        # Look for default routes (0.0.0.0/0) that redirect traffic
        default_route_to_appliance = None
        for route in virtual_appliance_routes:
            if route.get("address_prefix") == "0.0.0.0/0":
                default_route_to_appliance = route
                break

        if default_route_to_appliance:
            # UDR overrides the configured outbound mechanism
            effective_summary["overridden_by_udr"] = True
            effective_summary["effective_mechanism"] = "virtualAppliance"
            appliance_ip = default_route_to_appliance.get(
                "next_hop_ip_address", "unknown"
            )
            effective_summary["virtual_appliance_ips"] = [appliance_ip]

            if outbound_type == "loadBalancer":
                effective_summary["warnings"].append(
                    {
                        "level": "warning",
                        "message": (
                            f"Load Balancer outbound configuration detected but "
                            f"UDR forces traffic to virtual appliance ({appliance_ip})"
                        ),
                        "impact": (
                            "The Load Balancer public IPs are not the effective "
                            "outbound IPs"
                        ),
                    }
                )
                effective_summary["description"] = (
                    f"Traffic is routed through virtual appliance {appliance_ip} "
                    f"via UDR (overriding Load Balancer)"
                )
            else:
                effective_summary["description"] = (
                    f"Traffic is routed through virtual appliance {appliance_ip} "
                    f"via UDR"
                )
        else:
            # No UDR override, use configured mechanism
            if outbound_type == "loadBalancer":
                if self.outbound_ips:
                    ip_list = ", ".join(self.outbound_ips)
                    effective_summary["description"] = (
                        f"Traffic uses Load Balancer with public IP(s): {ip_list}"
                    )
                else:
                    # Check if missing IPs is due to permission issues
                    has_lb_permission_issue = any(
                        f.code == FindingCode.PERMISSION_INSUFFICIENT_LB
                        for f in self.findings
                    )

                    if not has_lb_permission_issue:
                        # Only report missing IPs if not due to permissions
                        effective_summary["warnings"].append(
                            {
                                "level": "error",
                                "message": (
                                    "Load Balancer outbound type configured but no "
                                    "public IPs found"
                                ),
                                "impact": "Outbound connectivity may be broken",
                            }
                        )
                        effective_summary["description"] = (
                            "Load Balancer outbound configured but no public IPs detected"
                        )
                    else:
                        # Permission issue - set neutral description
                        effective_summary["description"] = (
                            "Load Balancer outbound type configured"
                        )
            elif outbound_type == "userDefinedRouting":
                if virtual_appliance_routes:
                    # Collect all virtual appliance IPs from routes
                    appliance_ips = list(
                        {
                            r.get("next_hop_ip_address", "unknown")
                            for r in virtual_appliance_routes
                            if r.get("next_hop_ip_address")
                        }
                    )
                    effective_summary["virtual_appliance_ips"] = appliance_ips
                    ips_str = ", ".join(appliance_ips)
                    effective_summary["description"] = (
                        f"User Defined Routing through virtual appliance(s): {ips_str}"
                    )
                else:
                    effective_summary["warnings"].append(
                        {
                            "level": "warning",
                            "message": (
                                "User Defined Routing configured but no virtual "
                                "appliance routes found"
                            ),
                            "impact": "May indicate misconfigured routing",
                        }
                    )
                    effective_summary["description"] = "User Defined Routing configured"
            elif outbound_type == "managedNATGateway":
                if self.outbound_ips:
                    ip_list = ", ".join(self.outbound_ips)
                    effective_summary["description"] = (
                        f"Managed NAT Gateway with outbound IPs: {ip_list}"
                    )
                else:
                    effective_summary["description"] = (
                        "Managed NAT Gateway (no outbound IPs detected)"
                    )

        return effective_summary

    def _display_outbound_summary(self, effective_summary: Dict[str, Any]) -> None:
        """
        Display a summary of the effective outbound configuration

        Args:
            effective_summary: Effective outbound configuration summary
        """
        mechanism = effective_summary["effective_mechanism"]
        description = effective_summary["description"]

        if effective_summary["overridden_by_udr"]:
            self.logger.warning("  %s", description)
            if effective_summary["load_balancer_ips"]:
                ips = ", ".join(effective_summary["load_balancer_ips"])
                self.logger.warning(
                    "    Load Balancer IPs (not effective): %s", ips
                )
        else:
            if mechanism == "loadBalancer" and effective_summary["load_balancer_ips"]:
                for ip in effective_summary["load_balancer_ips"]:
                    self.logger.warning("  Found outbound IP: %s", ip)
            elif (mechanism == "virtualAppliance" and
                  effective_summary["virtual_appliance_ips"]):
                for ip in effective_summary["virtual_appliance_ips"]:
                    self.logger.warning("  Virtual appliance IP: %s", ip)
            elif (mechanism == "managedNATGateway" and
                  effective_summary["load_balancer_ips"]):
                for ip in effective_summary["load_balancer_ips"]:
                    self.logger.warning("  NAT Gateway outbound IP: %s", ip)

        # Display warnings
        for warning in effective_summary.get("warnings", []):
            level = warning["level"]
            message = warning["message"]
            if level == "error":
                self.logger.error("    %s", message)
            else:
                self.logger.warning("    %s", message)

    def _analyze_load_balancer_outbound(self, show_details: bool = False) -> None:  # pylint: disable=too-many-branches
        """
        Analyze load balancer outbound configuration

        Args:
            show_details: Enable detailed logging
        """
        self.logger.info("  - Analyzing Load Balancer outbound configuration...")

        # Get the managed cluster's load balancer
        mc_rg = self.cluster_info.get("node_resource_group", "")
        if not mc_rg:
            if show_details:
                self.logger.info("    No node resource group found")
            return

        try:
            # List load balancers in the managed resource group
            load_balancers_list = list(
                self.network_client.load_balancers.list(mc_rg)
            )

            if not load_balancers_list:
                if show_details:
                    self.logger.info("    No load balancers found in %s", mc_rg)
                return

        except (ResourceNotFoundError, HttpResponseError) as e:
            # Check if this is an authorization error
            if isinstance(e, HttpResponseError):
                if self._check_authorization_error(e, 'LoadBalancer', mc_rg):
                    return  # Authorization error, finding already created
            self.logger.warning(
                "Failed to list load balancers in %s: %s", mc_rg, e
            )
            return

        # Process load balancers quietly and only report the final results
        for lb in load_balancers_list:
            lb_name = lb.name
            if not lb_name:
                continue

            # Check outbound rules first
            outbound_rules = lb.outbound_rules or []
            frontend_configs = lb.frontend_ip_configurations or []

            # Collect frontend config IDs that might have outbound IPs
            frontend_config_ids = []

            # Add frontend configs from outbound rules (main path for AKS)
            for rule in outbound_rules:
                frontend_ips = rule.frontend_ip_configurations or []

                for frontend_ip in frontend_ips:
                    if frontend_ip.id:
                        frontend_config_ids.append(frontend_ip.id)

            # Also add all direct frontend configs (standard LB without outbound rules)
            for frontend in frontend_configs:
                if frontend.id:
                    frontend_config_ids.append(frontend.id)

            # Process each frontend config
            for config_id in frontend_config_ids:
                # Extract load balancer name and frontend config name from ID
                parts = config_id.split("/")
                if len(parts) >= 11:
                    config_name = parts[10]  # Frontend IP config name

                    try:
                        # Get the frontend IP configuration details
                        frontend_config = self.network_client.load_balancer_frontend_ip_configurations.get(  # pylint: disable=line-too-long
                            mc_rg, lb_name, config_name
                        )

                        if frontend_config and frontend_config.public_ip_address:
                            public_ip_id = frontend_config.public_ip_address.id
                            if public_ip_id:
                                # Get public IP details
                                ip_info = self._get_public_ip_details(public_ip_id)

                                if ip_info and ip_info.get("ip_address"):
                                    ip_address = ip_info["ip_address"]
                                    if ip_address not in self.outbound_ips:
                                        self.outbound_ips.append(ip_address)

                    except (ResourceNotFoundError, HttpResponseError) as e:
                        self.logger.debug(
                            "Failed to get frontend config %s: %s", config_name, e
                        )
                        continue

        # Summary of outbound IP discovery will be handled by _display_outbound_summary
        if show_details and not self.outbound_ips:
            self.logger.info("    No outbound IPs detected")

    def _analyze_udr_outbound(self) -> None:
        """Analyze User Defined Routing outbound configuration"""
        self.logger.info("  - Analyzing User Defined Routing configuration...")

        # Use pre-computed route table analysis
        udr_analysis = self.route_table_analysis

        # Store UDR analysis results
        self.outbound_analysis = {
            "type": "userDefinedRouting",
            "route_tables": udr_analysis.get("route_tables", []),
            "critical_routes": udr_analysis.get("critical_routes", []),
            "virtual_appliance_routes": udr_analysis.get(
                "virtual_appliance_routes", []
            ),
            "internet_routes": udr_analysis.get("internet_routes", []),
        }

    def _analyze_nat_gateway_outbound(
        self, show_details: bool = False, outbound_type: str = "managedNATGateway"
    ) -> None:
        """
        Analyze NAT Gateway outbound configuration

        Args:
            show_details: Enable detailed logging
            outbound_type: Type of NAT Gateway ('managedNATGateway' or 'userAssignedNATGateway')
        """
        self.logger.info("  - Analyzing NAT Gateway configuration...")

        if outbound_type == "managedNATGateway":
            # Managed NAT Gateway - look in the node resource group
            self._analyze_managed_nat_gateway(show_details)
        elif outbound_type == "userAssignedNATGateway":
            # User-assigned NAT Gateway - check subnets for attached NAT Gateway
            self._analyze_user_assigned_nat_gateway(show_details)

    def _analyze_managed_nat_gateway(self, show_details: bool = False) -> None:
        """
        Analyze managed NAT Gateway configuration (in node resource group)

        Args:
            show_details: Enable detailed logging
        """
        # Get the managed cluster's resource group
        mc_rg = self.cluster_info.get("node_resource_group", "")
        if not mc_rg:
            if show_details:
                self.logger.info("    No node resource group found")
            return

        try:
            # List NAT Gateways in the managed resource group
            nat_gateways_list = list(self.network_client.nat_gateways.list(mc_rg))

            if not nat_gateways_list:
                if show_details:
                    self.logger.info("    No NAT Gateways found in %s", mc_rg)
                return

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.warning(
                "Failed to list NAT Gateways in %s: %s", mc_rg, e
            )
            return

        # Process each NAT Gateway
        for natgw in nat_gateways_list:
            natgw_name = natgw.name
            if not natgw_name:
                continue

            self.logger.info("    Found NAT Gateway: %s", natgw_name)

            # Get public IP prefixes and public IPs associated with NAT Gateway
            public_ip_prefixes = natgw.public_ip_prefixes or []
            public_ips = natgw.public_ip_addresses or []

            # Extract IPs from public IP resources
            for public_ip_ref in public_ips:
                public_ip_id = public_ip_ref.id if public_ip_ref else None
                if public_ip_id:
                    public_ip_info = self._get_public_ip_details(public_ip_id)
                    if public_ip_info:
                        ip_address = public_ip_info.get("ip_address", "")
                        if ip_address:
                            self.outbound_ips.append(ip_address)
                            if show_details:
                                self.logger.info("      Public IP: %s", ip_address)

            # Extract IPs from public IP prefixes
            for prefix_ref in public_ip_prefixes:
                prefix_id = prefix_ref.get("id", "")
                if prefix_id:
                    prefix_info = self._get_public_ip_prefix_details(prefix_id)
                    if prefix_info:
                        ip_prefix = prefix_info.get("ip_prefix", "")
                        if ip_prefix:
                            # For prefixes, note the range
                            if show_details:
                                self.logger.info("      Public IP Prefix: %s", ip_prefix)
                            # Extract first IP from prefix for outbound IP tracking
                            try:
                                import ipaddress  # pylint: disable=import-outside-toplevel

                                # Validate the prefix
                                ipaddress.ip_network(ip_prefix, strict=False)
                                self.outbound_ips.append(f"{ip_prefix} (range)")
                            except Exception:  # pylint: disable=broad-except
                                self.outbound_ips.append(f"{ip_prefix} (prefix)")

        if not self.outbound_ips and show_details:
            self.logger.info("    No outbound IPs detected from NAT Gateway")

    def _analyze_user_assigned_nat_gateway(self, show_details: bool = False) -> None:
        """
        Analyze user-assigned NAT Gateway configuration (attached to subnet)

        Args:
            show_details: Enable detailed logging
        """
        # Get subnet IDs from VMSS configuration
        subnet_ids = self._get_vmss_subnet_ids()

        if not subnet_ids:
            if show_details:
                self.logger.info("    No subnets found in VMSS configuration")
            return

        # Check each subnet for NAT Gateway
        for subnet_id in subnet_ids:
            self._process_subnet_nat_gateway(subnet_id, show_details)

        if not self.outbound_ips and show_details:
            self.logger.info("    No outbound IPs detected from user-assigned NAT Gateway")

    def _get_vmss_subnet_ids(self) -> Set[str]:
        """Extract unique subnet IDs from VMSS network interfaces."""
        subnet_ids = set()

        for vmss_config in self.vmss_info:
            vm_profile = vmss_config.get("virtual_machine_profile", {})
            network_interfaces = vm_profile.get("network_profile", {}).get("network_interface_configurations", [])
            for nic in network_interfaces:
                for ip_config in nic.get("ip_configurations", []):
                    subnet_id = ip_config.get("subnet", {}).get("id")
                    if subnet_id:
                        subnet_ids.add(subnet_id)

        return subnet_ids

    def _process_subnet_nat_gateway(self, subnet_id: str, show_details: bool) -> None:
        """Process a subnet to check for attached NAT Gateway."""
        # Parse subnet resource ID
        # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/
        #         Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}
        parts = subnet_id.split("/")
        if len(parts) < 11:
            if show_details:
                self.logger.warning("    Invalid subnet ID format: %s", subnet_id)
            return

        resource_group = parts[4]
        vnet_name = parts[8]
        subnet_name = parts[10]

        try:
            subnet_info = self.network_client.subnets.get(
                resource_group_name=resource_group,
                virtual_network_name=vnet_name,
                subnet_name=subnet_name,
            )

            if not subnet_info.nat_gateway:
                return

            self._extract_nat_gateway_ips(subnet_info.nat_gateway.id, show_details)
        except (ResourceNotFoundError, HttpResponseError) as ex:
            if show_details:
                self.logger.warning("    Failed to get subnet info: %s", str(ex))

    def _extract_nat_gateway_ips(self, nat_gw_id: str, show_details: bool) -> None:
        """Extract public IPs from NAT Gateway."""
        nat_gw_parsed = self._parse_resource_id(nat_gw_id)
        natgw = self.network_client.nat_gateways.get(
            nat_gw_parsed["resource_group"],
            nat_gw_parsed["resource_name"]
        )

        # Process public IPs
        for public_ip_ref in (natgw.public_ip_addresses or []):
            self._process_nat_gateway_public_ip(public_ip_ref, show_details)

        # Process public IP prefixes
        for prefix_ref in (natgw.public_ip_prefixes or []):
            self._process_nat_gateway_ip_prefix(prefix_ref, show_details)

    def _process_nat_gateway_public_ip(self, public_ip_ref: Any, show_details: bool) -> None:
        """Process a single public IP from NAT Gateway."""
        public_ip_id = public_ip_ref.id if public_ip_ref else None
        if not public_ip_id:
            return

        public_ip_info = self._get_public_ip_details(public_ip_id)
        if public_ip_info:
            ip_address = public_ip_info.get("ip_address", "")
            if ip_address:
                self.outbound_ips.append(ip_address)
                if show_details:
                    self.logger.info("      Public IP: %s", ip_address)

    def _process_nat_gateway_ip_prefix(self, prefix_ref: Any, show_details: bool) -> None:
        """Process a single IP prefix from NAT Gateway."""
        prefix_id = (
            prefix_ref.get("id", "")
            if hasattr(prefix_ref, 'get')
            else (prefix_ref.id if prefix_ref else "")
        )
        if not prefix_id:
            return

        prefix_info = self._get_public_ip_prefix_details(prefix_id)
        if not prefix_info:
            return

        ip_prefix = prefix_info.get("ip_prefix", "")
        if ip_prefix:
            if show_details:
                self.logger.info("      Public IP Prefix: %s", ip_prefix)
            # Validate and add the prefix
            try:
                import ipaddress  # pylint: disable=import-outside-toplevel
                ipaddress.ip_network(ip_prefix, strict=False)
                self.outbound_ips.append(f"{ip_prefix} (range)")
            except Exception:  # pylint: disable=broad-except
                self.outbound_ips.append(f"{ip_prefix} (prefix)")

    def _get_public_ip_details(self, public_ip_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a public IP resource

        Args:
            public_ip_id: Azure resource ID of the public IP

        Returns:
            Dictionary with public IP details or None if error
        """
        try:
            # Parse public IP ID to extract components
            parsed = self._parse_resource_id(public_ip_id)
            subscription_id = parsed["subscription_id"]
            resource_group = parsed["resource_group"]
            public_ip_name = parsed["resource_name"]

            # Create network client for public IP's subscription if different
            if subscription_id != self.subscription_id:
                from azure.mgmt.network import NetworkManagementClient  # pylint: disable=import-outside-toplevel

                network_client = NetworkManagementClient(
                    self.credential, subscription_id
                )
            else:
                network_client = self.network_client

            # Get public IP details
            public_ip = network_client.public_ip_addresses.get(
                resource_group, public_ip_name
            )

            # Convert to dictionary with snake_case keys
            return self._to_dict(public_ip)

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.debug(
                "Error getting public IP details for %s: %s", public_ip_id, e
            )
            return None
        except Exception as e:  # pylint: disable=broad-except
            self.logger.debug(
                "Error parsing public IP ID %s: %s", public_ip_id, e
            )
            return None

    def _get_public_ip_prefix_details(
        self, prefix_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a public IP prefix resource

        Args:
            prefix_id: Azure resource ID of the public IP prefix

        Returns:
            Dictionary with public IP prefix details or None if error
        """
        try:
            # Parse public IP prefix ID to extract components
            parsed = self._parse_resource_id(prefix_id)
            subscription_id = parsed["subscription_id"]
            resource_group = parsed["resource_group"]
            prefix_name = parsed["resource_name"]

            # Create network client for prefix's subscription if different
            if subscription_id != self.subscription_id:
                from azure.mgmt.network import NetworkManagementClient  # pylint: disable=import-outside-toplevel

                network_client = NetworkManagementClient(
                    self.credential, subscription_id
                )
            else:
                network_client = self.network_client

            # Get public IP prefix details
            public_ip_prefix = network_client.public_ip_prefixes.get(
                resource_group, prefix_name
            )

            # Convert to dictionary with snake_case keys
            return self._to_dict(public_ip_prefix)

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.debug(
                "Error getting public IP prefix details for %s: %s", prefix_id, e
            )
            return None
        except Exception as e:  # pylint: disable=broad-except
            self.logger.debug(
                "Error parsing public IP prefix ID %s: %s", prefix_id, e
            )
            return None

    def _parse_resource_id(self, resource_id: str) -> Dict[str, str]:
        """
        Parse an Azure resource ID into its components

        Args:
            resource_id: Full Azure resource ID

        Returns:
            Dictionary with parsed components
        """
        parts = resource_id.split("/")
        if len(parts) < 9:
            raise ValueError(f"Invalid resource ID format: {resource_id}")

        return {
            "subscription_id": parts[2],
            "resource_group": parts[4],
            "provider": parts[6],
            "resource_type": parts[7],
            "resource_name": parts[8],
        }

    def _to_dict(self, obj: Any) -> Dict[str, Any]:
        """
        Convert Azure SDK object to dictionary with snake_case keys

        Args:
            obj: Azure SDK object

        Returns:
            Dictionary representation with snake_case keys
        """
        if not hasattr(obj, "as_dict"):
            return {}

        result = obj.as_dict()

        # Convert camelCase keys to snake_case
        def camel_to_snake(name: str) -> str:
            import re  # pylint: disable=import-outside-toplevel,redefined-outer-name,reimported

            name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
            return re.sub("([a-z0-9])([A-Z])", r"\1_\2", name).lower()

        def convert_keys(obj_dict: Any) -> Any:
            if isinstance(obj_dict, dict):
                return {
                    camel_to_snake(k): convert_keys(v) for k, v in obj_dict.items()
                }
            if isinstance(obj_dict, list):
                return [convert_keys(item) for item in obj_dict]
            return obj_dict

        return convert_keys(result)
