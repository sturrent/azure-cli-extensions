"""
MisconfigurationAnalyzer Module
Analyzes AKS cluster misconfigurations and generates findings

Migrated from Azure CLI subprocess to Azure SDK for Python.
"""

import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError


class MisconfigurationAnalyzer:  # pylint: disable=too-few-public-methods
    """Analyzes AKS cluster for potential misconfigurations and failures"""

    def __init__(
        self,
        clients: Dict[str, Any],
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the MisconfigurationAnalyzer

        Args:
            clients: Dictionary of Azure SDK client instances
                    (network_client, privatedns_client, etc.)
            logger: Optional logger instance
        """
        self.clients = clients
        self.network_client = clients.get('network_client')
        self.privatedns_client = clients.get('privatedns_client')
        self.credential = clients.get('credential')  # Store credential for cross-subscription clients
        self.logger = logger or logging.getLogger(__name__)
        self._cluster_stopped = False

    def _get_privatedns_client_for_zone(self, dns_zone_resource_id: str):
        """
        Get a PrivateDnsManagementClient scoped to the subscription of the DNS zone.

        This handles cross-subscription BYO private DNS zones where the DNS zone
        is in a different subscription than the AKS cluster.

        Args:
            dns_zone_resource_id: Full resource ID of the private DNS zone

        Returns:
            PrivateDnsManagementClient instance or None if creation fails
        """
        try:
            # Parse subscription ID from resource ID
            #  Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/privateDnsZones/{zone}
            parts = dns_zone_resource_id.split("/")
            if len(parts) < 3 or parts[1] != "subscriptions":
                self.logger.warning("Invalid DNS zone resource ID format: %s", dns_zone_resource_id)
                return None

            dns_zone_subscription = parts[2]

            # Check if we need a different client (cross-subscription scenario)
            current_subscription = self.clients.get('subscription_id')
            if dns_zone_subscription == current_subscription:
                # Same subscription, use existing client
                return self.privatedns_client

            # Cross-subscription: create new client if we have credentials
            if not self.credential:
                self.logger.warning(
                    "BYO private DNS zone is in different subscription (%s) but no credential available for cross-subscription access",  # pylint: disable=line-too-long
                    dns_zone_subscription
                )
                return None

            # Import here to avoid circular imports
            from azure.mgmt.privatedns import PrivateDnsManagementClient

            self.logger.info(
                "Creating cross-subscription PrivateDnsManagementClient for subscription %s",
                dns_zone_subscription
            )

            return PrivateDnsManagementClient(
                credential=self.credential,
                subscription_id=dns_zone_subscription
            )
        except Exception as e:  # pylint: disable=broad-except
            self.logger.warning("Could not create cross-subscription DNS client: %s", e)
            return None

    def analyze(
        self,
        cluster_info: Dict[str, Any],
        *,
        outbound_analysis: Dict[str, Any],
        outbound_ips: List[str],
        private_dns_analysis: Dict[str, Any],
        api_server_access_analysis: Dict[str, Any],
        nsg_analysis: Dict[str, Any],
        api_probe_results: Optional[Dict[str, Any]],
        vmss_analysis: List[Dict[str, Any]],
        permission_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Analyze cluster for misconfigurations and generate findings

        Args:
            cluster_info: Cluster information from AKS API
            outbound_analysis: Outbound connectivity analysis results
            outbound_ips: List of outbound IP addresses
            private_dns_analysis: Private DNS configuration analysis
            api_server_access_analysis: API server access analysis results
            nsg_analysis: NSG configuration analysis results
            api_probe_results: API connectivity probe results
            vmss_analysis: VMSS configuration analysis
            permission_findings: Optional list of permission-related findings

        Returns:
            Tuple of (findings list, cluster_stopped flag)
        """
        self.logger.info("Analyzing potential misconfigurations...")

        findings = []
        permission_findings = permission_findings or []

        # Check cluster power state
        self._check_cluster_power_state(cluster_info, findings)

        # Check cluster operational state
        self._check_cluster_provisioning_state(cluster_info, findings)

        # Check node pool states
        self._check_node_pool_states(cluster_info, findings)

        # Check private DNS configuration for private clusters
        api_server_profile = cluster_info.get("api_server_access_profile")
        is_private = (
            api_server_profile.get("enable_private_cluster", False)
            if api_server_profile else False
        )

        if is_private:
            self._analyze_private_dns_issues(
                cluster_info,
                private_dns_analysis,
                findings
            )

        # Check for missing outbound IPs
        self._check_outbound_ips(cluster_info, outbound_ips, findings, permission_findings)

        # Check VNet configuration issues
        self._analyze_vnet_issues(vmss_analysis, findings)

        # Check UDR configuration issues
        self._analyze_udr_issues(outbound_analysis, findings)

        # Check API server access configuration issues
        self._analyze_api_server_access_issues(
            api_server_access_analysis,
            findings
        )

        # Check NSG configuration issues
        self._analyze_nsg_issues(nsg_analysis, findings, permission_findings)

        # Check connectivity test results (only if cluster is running)
        if not self._cluster_stopped:
            self._analyze_connectivity_test_results(
                api_probe_results,
                findings
            )

        return findings, self._cluster_stopped

    def _check_cluster_power_state(
        self,
        cluster_info: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Check cluster power state"""
        power_state = cluster_info.get("power_state", {})
        power_code = (
            power_state.get("code", "Unknown")
            if isinstance(power_state, dict)
            else str(power_state)
        )

        if power_code.lower() == "stopped":
            findings.append({
                "severity": "warning",
                "code": "CLUSTER_STOPPED",
                "message": "Cluster is in stopped state",
                "recommendation": (
                    "Start the cluster using 'az aks start' before running "
                    "connectivity tests or accessing cluster resources"
                ),
            })
            self._cluster_stopped = True
        else:
            self._cluster_stopped = False

    def _check_cluster_provisioning_state(
        self,
        cluster_info: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Check cluster operational/provisioning state"""
        provisioning_state = cluster_info.get("provisioning_state", "")
        if provisioning_state.lower() == "failed":
            # Try to get detailed error information from cluster status
            error_info = self._get_cluster_status_error(cluster_info)

            if error_info:
                error_code, detailed_error = error_info
                findings.append({
                    "severity": "critical",
                    "code": "CLUSTER_OPERATION_FAILURE",
                    "message": f"Cluster failed with error: {detailed_error}",
                    "error_code": error_code,
                    "recommendation": (
                        "Check Azure Activity Log for detailed failure "
                        "information and contact Azure support if needed"
                    ),
                })
            else:
                # No detailed error available - indicate this clearly instead
                # of showing fake/generic error
                findings.append({
                    "severity": "critical",
                    "code": "CLUSTER_OPERATION_FAILURE",
                    "message": (
                        f"Cluster provisioning failed (state: "
                        f"{provisioning_state}). Detailed error information "
                        f"not available."
                    ),
                    "recommendation": (
                        "Check Azure Activity Log or Azure Portal for "
                        "detailed failure information. Run "
                        "'az aks show -n <cluster-name> -g <resource-group>' "
                        "to see current cluster status."
                    ),
                })

    def _check_node_pool_states(
        self,
        cluster_info: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Check node pool provisioning states"""
        failed_node_pools = []
        agent_pool_profiles = cluster_info.get("agent_pool_profiles", [])
        for pool in agent_pool_profiles:
            pool_state = pool.get("provisioning_state", "")
            if pool_state.lower() == "failed":
                failed_node_pools.append(pool.get("name", "unknown"))

        if failed_node_pools:
            findings.append({
                "severity": "critical",
                "code": "NODE_POOL_FAILURE",
                "message": (
                    f"Node pools in failed state: "
                    f"{', '.join(failed_node_pools)}"
                ),
                "recommendation": (
                    "Check node pool configuration and Azure Activity Log "
                    "for detailed failure information"
                ),
            })

    def _check_outbound_ips(
        self,
        cluster_info: Dict[str, Any],
        outbound_ips: List[str],
        findings: List[Dict[str, Any]],
        permission_findings: List[Dict[str, Any]]
    ) -> None:
        """Check for missing outbound IPs"""
        network_profile = cluster_info.get("network_profile", {})
        outbound_type = network_profile.get("outbound_type", "loadBalancer")

        # Check if we have permission issues that could prevent IP detection
        has_lb_permission_issue = any(
            f.get("code") == "PERMISSION_INSUFFICIENT_LB"
            for f in permission_findings
        )
        has_vnet_permission_issue = any(
            f.get("code") == "PERMISSION_INSUFFICIENT_VNET"
            for f in permission_findings
        )

        # Debug logging
        self.logger.debug(
            "Checking outbound IPs: outbound_ips=%s, outbound_type=%s, "
            "has_lb_permission_issue=%s, has_vnet_permission_issue=%s, "
            "permission_findings_count=%d",
            outbound_ips, outbound_type, has_lb_permission_issue,
            has_vnet_permission_issue, len(permission_findings)
        )

        # Only report missing IPs if:
        # 1. No outbound IPs detected
        # 2. Outbound type requires IPs (loadBalancer or managedNATGateway)
        # 3. It's not due to permission issues
        if (not outbound_ips and
                outbound_type in ["loadBalancer", "managedNATGateway"] and
                not has_lb_permission_issue and
                not has_vnet_permission_issue):
            self.logger.debug("Adding NO_OUTBOUND_IPS finding")
            findings.append({
                "severity": "warning",
                "code": "NO_OUTBOUND_IPS",
                "message": (
                    f"No outbound IP addresses detected for {outbound_type} "
                    f"outbound type"
                ),
                "recommendation": (
                    "Verify outbound connectivity configuration. Check that "
                    "the load balancer or NAT gateway has public IPs "
                    "assigned."
                ),
            })
        else:
            self.logger.debug("Skipping NO_OUTBOUND_IPS finding (permission issues detected or IPs found)")

    def _get_cluster_status_error(
        self,
        cluster_info: Dict[str, Any]
    ) -> Optional[Tuple[Optional[str], str]]:
        """Get detailed cluster error information from status field"""
        try:
            status = cluster_info.get("status", {})
            if isinstance(status, dict):
                error_detail = status.get("errordetail", {})
                if isinstance(error_detail, dict):
                    error_message = error_detail.get("message", "")
                    error_code = error_detail.get("code", "")

                    if error_message:
                        if error_code:
                            return (error_code, f"{error_code}: {error_message}")
                        return (None, error_message)

                provisioning_error = status.get("provisioning_error")
                if provisioning_error:
                    return (None, str(provisioning_error))

            return None

        except Exception as e:  # pylint: disable=broad-except
            self.logger.info("Could not retrieve cluster status error: %s", e)
            return None

    def _analyze_private_dns_issues(
        self,
        cluster_info: Dict[str, Any],
        private_dns_analysis: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze private DNS configuration issues"""
        if not private_dns_analysis:
            return

        api_server_profile = cluster_info.get("api_server_access_profile", {})
        private_dns_zone = api_server_profile.get("private_dns_zone", "")

        if private_dns_zone == "system":
            self._check_system_private_dns_issues(cluster_info, findings)
        elif private_dns_zone and private_dns_zone != "system":
            self._check_private_dns_vnet_links(
                cluster_info,
                private_dns_zone,
                findings
            )

    def _check_system_private_dns_issues(
        self,
        cluster_info: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Check system-managed private DNS zone issues"""
        try:
            # Get the cluster's managed resource group (MC_ resource group)
            # System-managed DNS zones are created in this resource group
            node_resource_group = cluster_info.get("node_resource_group", "")
            if not node_resource_group:
                self.logger.info("No node_resource_group found, skipping system DNS check")
                return

            # List all private DNS zones in the subscription
            # Note: Using list() to get all zones across subscription
            # (not limited to one RG)
            zones_list = list(self.privatedns_client.private_zones.list())

            aks_private_zones = []
            for zone in zones_list:
                zone_name = zone.name
                if "azmk8s.io" in zone_name and "privatelink" in zone_name:
                    # Convert to dict with snake_case keys
                    zone_dict = self._to_dict(zone.as_dict())
                    # Parse resource group from zone ID
                    parsed = self._parse_resource_id(zone.id)
                    zone_rg = parsed["resource_group"]
                    zone_dict["resource_group"] = zone_rg

                    # Only include zones in the cluster's MC resource group
                    # This avoids checking other clusters' DNS zones (and duplicate findings)
                    if zone_rg.lower() != node_resource_group.lower():
                        continue

                    aks_private_zones.append(zone_dict)

            if not aks_private_zones:
                return

            for zone in aks_private_zones:
                zone_name = zone.get("name", "")
                zone_rg = zone.get("resource_group", "")

                if zone_rg and zone_name:
                    # Pass actual zone name for both API calls and display
                    self._check_dns_server_vnet_links(
                        zone_rg,
                        zone_name,
                        cluster_info,
                        findings
                    )

        except Exception as e:  # pylint: disable=broad-except
            self.logger.info("Could not analyze system private DNS issues: %s", e)

    def _check_dns_server_vnet_links(
        self,
        zone_rg: str,
        zone_name: str,
        cluster_info: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Check if VNets with custom DNS servers are properly linked
        to private DNS zone

        Args:
            zone_rg: Resource group containing the zone
            zone_name: Zone name for both API calls and display
            cluster_info: Cluster information
            findings: List to append findings to
        """
        try:
            # List VNet links for the private DNS zone using SDK
            # (replaces: az network private-dns link vnet list)
            links_list = list(
                self.privatedns_client.virtual_network_links.list(
                    zone_rg,
                    zone_name
                )
            )

            linked_vnet_ids = []
            for link in links_list:
                if link.virtual_network:
                    linked_vnet_ids.append(link.virtual_network.id)

            cluster_vnets = self._get_cluster_vnets_with_dns(cluster_info)

            for vnet_info in cluster_vnets:
                vnet_name = vnet_info.get("name", "")
                dns_servers = vnet_info.get("dns_servers", [])

                if dns_servers:
                    for dns_server in dns_servers:
                        dns_host_vnet = self._find_dns_server_host_vnet(
                            cluster_info,
                            dns_server
                        )

                        if (dns_host_vnet and
                                dns_host_vnet.get("id") not in linked_vnet_ids):
                            dns_host_vnet_name = dns_host_vnet.get(
                                "name",
                                "unknown"
                            )
                            findings.append({
                                "severity": "critical",
                                "code": "PDNS_DNS_HOST_VNET_LINK_MISSING",
                                "message": (
                                    f"DNS server {dns_server} is hosted in "
                                    f"VNet {dns_host_vnet_name} but this VNet "
                                    f"is not linked to private DNS zone "
                                    f"{zone_name}. Cluster VNet {vnet_name} "
                                    f"uses this DNS server."
                                ),
                                "recommendation": (
                                    f"Link VNet {dns_host_vnet_name} to "
                                    f"private DNS zone {zone_name} to ensure "
                                    f"proper DNS resolution for the private "
                                    f"cluster"
                                ),
                            })

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.info("Could not check DNS server VNet links: %s", e)
        except Exception as e:  # pylint: disable=broad-except
            self.logger.info("Could not check DNS server VNet links: %s", e)

    def _get_cluster_vnets_with_dns(self, cluster_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get cluster VNets with their DNS configurations"""
        vnets = []

        try:
            # Get VNets from agent pools
            agent_pools = cluster_info.get("agent_pool_profiles", [])

            for pool in agent_pools:
                vnet_subnet_id = pool.get("vnet_subnet_id")

                if not vnet_subnet_id:
                    continue

                # Parse VNet info from subnet ID
                # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/
                #         Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}
                parts = vnet_subnet_id.split("/")
                if len(parts) < 9:
                    continue

                vnet_rg = parts[4]
                vnet_name = parts[8]

                # Get VNet to check DNS servers
                try:
                    vnet = self.network_client.virtual_networks.get(vnet_rg, vnet_name)
                    dhcp_options = vnet.dhcp_options
                    dns_servers = dhcp_options.dns_servers if dhcp_options else []

                    if dns_servers:
                        vnets.append({
                            "name": vnet_name,
                            "resource_group": vnet_rg,
                            "id": vnet.id,
                            "dns_servers": dns_servers
                        })
                except Exception as e:  # pylint: disable=broad-except
                    self.logger.debug("Could not get VNet %s: %s", vnet_name, e)

        except Exception as e:  # pylint: disable=broad-except
            self.logger.debug("Could not get cluster VNets: %s", e)

        return vnets

    def _check_vnet_for_dns_ip(self, vnet, dns_ip, vnet_rg):
        """Check if VNet contains DNS IP and return match info if found."""
        address_space = vnet.address_space
        if not address_space:
            return None

        for prefix in address_space.address_prefixes or []:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
                if dns_ip in network:
                    return {
                        "id": vnet.id,
                        "name": vnet.name,
                        "resource_group": vnet_rg,
                        "prefix_len": network.prefixlen
                    }
            except Exception:  # pylint: disable=broad-except
                continue
        return None

    def _find_dns_server_host_vnet(
        self,
        cluster_info: Dict[str, Any],
        dns_server_ip: str
    ) -> Optional[Dict[str, str]]:
        """Find which VNet hosts the given DNS server IP

        Checks VNets that are peered with the cluster VNet to find where
        the custom DNS server is hosted.
        """
        try:
            # First, get the cluster's VNet
            agent_pools = cluster_info.get("agent_pool_profiles", [])
            if not agent_pools:
                return None

            vnet_subnet_id = agent_pools[0].get("vnet_subnet_id")
            if not vnet_subnet_id:
                return None

            # Parse cluster VNet info from subnet ID
            parts = vnet_subnet_id.split("/")
            if len(parts) < 9:
                return None

            cluster_vnet_rg = parts[4]
            cluster_vnet_name = parts[8]

            # Get cluster VNet to find peerings
            try:
                cluster_vnet = self.network_client.virtual_networks.get(
                    cluster_vnet_rg,
                    cluster_vnet_name
                )
            except Exception as e:  # pylint: disable=broad-except
                self.logger.debug("Could not get cluster VNet: %s", e)
                return None

            dns_ip = ipaddress.ip_address(dns_server_ip)

            # Track the best match (most specific network)
            best_match = None
            smallest_prefix_len = -1

            # Get peerings
            peerings = cluster_vnet.virtual_network_peerings or []

            for peering in peerings:
                if not peering.remote_virtual_network:
                    continue

                # Parse remote VNet ID
                remote_vnet_id = peering.remote_virtual_network.id
                remote_parts = remote_vnet_id.split("/")
                if len(remote_parts) < 9:
                    continue

                remote_vnet_rg = remote_parts[4]
                remote_vnet_name = remote_parts[8]

                try:
                    # Get the peered VNet
                    remote_vnet = self.network_client.virtual_networks.get(
                        remote_vnet_rg,
                        remote_vnet_name
                    )

                    # Check if this VNet contains the DNS IP
                    match = self._check_vnet_for_dns_ip(remote_vnet, dns_ip, remote_vnet_rg)
                    if match and match["prefix_len"] > smallest_prefix_len:
                        smallest_prefix_len = match["prefix_len"]
                        best_match = {
                            "id": match["id"],
                            "name": match["name"],
                            "resource_group": match["resource_group"]
                        }

                except Exception as e:  # pylint: disable=broad-except
                    self.logger.debug("Could not get peered VNet %s: %s", remote_vnet_name, e)
                    continue

            return best_match

        except Exception as e:  # pylint: disable=broad-except
            self.logger.info("Could not find DNS server host VNet: %s", e)

        return None

    def _check_private_dns_vnet_links(
        self,
        cluster_info: Dict[str, Any],
        private_dns_zone: str,
        findings: List[Dict[str, Any]]
    ) -> None:
        """Check if VNets are properly linked to private DNS zone"""
        try:
            # Determine which privatedns client to use (handle cross-subscription BYO DNS zones)
            dns_client = self.privatedns_client  # Default to cluster subscription client

            if "/" in private_dns_zone:
                # BYO private DNS zone with full resource ID
                dns_zone_parts = private_dns_zone.split("/")
                dns_zone_rg = (
                    dns_zone_parts[4]
                    if len(dns_zone_parts) > 4
                    else ""
                )
                dns_zone_name = (
                    dns_zone_parts[-1]
                    if dns_zone_parts
                    else ""
                )

                # Try to get cross-subscription client if needed
                cross_sub_client = self._get_privatedns_client_for_zone(private_dns_zone)
                if cross_sub_client:
                    dns_client = cross_sub_client
                else:
                    self.logger.warning(
                        "Could not access BYO private DNS zone in cross-subscription scenario: %s",
                        private_dns_zone
                    )
                    # Add informational finding about cross-subscription limitation
                    findings.append({
                        "severity": "info",
                        "code": "PDNS_CROSS_SUBSCRIPTION_ACCESS",
                        "message": (
                            f"BYO private DNS zone is in a different subscription: {private_dns_zone}. "
                            "VNet link validation skipped due to cross-subscription access limitations."
                        ),
                        "recommendation": (
                            "Ensure you have appropriate permissions to the DNS zone subscription, "
                            "or manually verify that cluster VNets are linked to the private DNS zone."
                        ),
                    })
                    return  # Skip validation if we can't access the DNS zone
            else:
                # System-managed DNS zone name without full path - search in current subscription
                dns_zone_name = private_dns_zone
                dns_zone_rg = self._find_private_dns_zone_rg(dns_zone_name)

            if dns_zone_rg and dns_zone_name:
                # List VNet links for the private DNS zone using SDK
                # (replaces: az network private-dns link vnet list)
                links_list = list(
                    dns_client.virtual_network_links.list(
                        dns_zone_rg,
                        dns_zone_name
                    )
                )

                cluster_vnet_ids = self._get_cluster_vnet_ids(cluster_info)
                linked_vnet_ids = []
                for link in links_list:
                    if link.virtual_network:
                        linked_vnet_ids.append(link.virtual_network.id)

                for vnet_id in cluster_vnet_ids:
                    if vnet_id not in linked_vnet_ids:
                        vnet_name = (
                            vnet_id.split("/")[-1]
                            if vnet_id
                            else "unknown"
                        )
                        findings.append({
                            "severity": "critical",
                            "code": "PDNS_DNS_HOST_VNET_LINK_MISSING",
                            "message": (
                                f"Cluster VNet {vnet_name} is not linked to "
                                f"private DNS zone {dns_zone_name}"
                            ),
                            "recommendation": (
                                "Link the cluster VNet to the private DNS "
                                "zone to ensure proper name resolution"
                            ),
                        })
        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.info("Could not analyze private DNS VNet links: %s", e)
        except Exception as e:  # pylint: disable=broad-except
            self.logger.info("Could not analyze private DNS VNet links: %s", e)

    def _find_private_dns_zone_rg(self, zone_name: str) -> str:
        """Find the resource group containing the private DNS zone"""
        try:
            # List all private DNS zones using SDK
            # (replaces: az network private-dns zone list)
            zones_list = list(self.privatedns_client.private_zones.list())

            for zone in zones_list:
                if zone.name == zone_name:
                    # Parse resource group from zone ID
                    parsed = self._parse_resource_id(zone.id)
                    return parsed["resource_group"]
        except (ResourceNotFoundError, HttpResponseError):
            pass
        except Exception:  # pylint: disable=broad-except
            pass
        return ""

    def _get_cluster_vnet_ids(self, cluster_info: Dict[str, Any]) -> List[str]:
        """Get VNet IDs associated with the cluster"""
        vnet_ids = []

        agent_pools = cluster_info.get("agent_pool_profiles", [])
        for pool in agent_pools:
            subnet_id = pool.get("vnet_subnet_id", "")
            if subnet_id:
                vnet_id = "/".join(subnet_id.split("/")[:-2])
                if vnet_id not in vnet_ids:
                    vnet_ids.append(vnet_id)

        return vnet_ids

    def _analyze_vnet_issues(
        self,
        vmss_analysis: List[Dict[str, Any]],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze VNet configuration issues"""
        # Placeholder for future VNet subnet capacity analysis
        # TODO: Implement VNet subnet capacity analysis

    def _analyze_udr_issues(
        self,
        outbound_analysis: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze User Defined Route configuration issues"""
        udr_analysis = outbound_analysis.get("udr_analysis")
        if not udr_analysis:
            return

        critical_routes = udr_analysis.get("critical_routes", [])
        va_routes = udr_analysis.get("virtual_appliance_routes", [])
        default_va_routes = [
            r for r in va_routes
            if r.get("address_prefix") == "0.0.0.0/0"
        ]

        for route in critical_routes:
            impact = route.get("impact", {})
            severity = impact.get("severity", "info")
            route_prefix = route.get("address_prefix", "")

            if (severity == "high" and
                    route_prefix == "0.0.0.0/0" and
                    default_va_routes):
                continue

            if severity == "critical":
                findings.append({
                    "severity": "critical",
                    "code": "UDR_CRITICAL_ROUTE",
                    "message": (
                        f"Critical UDR detected: {route.get('name', 'unnamed')} "
                        f"({route_prefix}) - {impact.get('description', '')}"
                    ),
                    "recommendation": (
                        "Review and modify the route table to ensure "
                        "essential AKS traffic can reach its destinations. "
                        "Consider using service tags or more specific routes."
                    ),
                })
            elif severity == "high":
                findings.append({
                    "severity": "error",
                    "code": "UDR_HIGH_IMPACT_ROUTE",
                    "message": (
                        f"High-impact UDR detected: "
                        f"{route.get('name', 'unnamed')} "
                        f"({route_prefix}) - {impact.get('description', '')}"
                    ),
                    "recommendation": (
                        "Verify that the virtual appliance or next hop can "
                        "properly handle this traffic and has appropriate "
                        "rules configured."
                    ),
                })

        if va_routes:
            if default_va_routes:
                outbound_type = outbound_analysis.get("type", "unknown")
                affected_services = []
                if any(
                    "azure_services" in r.get("impact", {}).get(
                        "affected_traffic",
                        []
                    )
                    for r in default_va_routes
                ):
                    affected_services.append("Azure services")
                if any(
                    "container_registry" in r.get("impact", {}).get(
                        "affected_traffic",
                        []
                    )
                    for r in default_va_routes
                ):
                    affected_services.append("container registries")

                base_message = (
                    f"Default route (0.0.0.0/0) redirects all internet "
                    f"traffic through virtual appliance at "
                    f"{default_va_routes[0].get('next_hop_ip_address', 'unknown IP')}. "
                    f"Outbound type is {outbound_type}."
                )
                if affected_services:
                    base_message += (
                        f" This affects: {', '.join(affected_services)}."
                    )

                findings.append({
                    "severity": "warning",
                    "code": "UDR_DEFAULT_ROUTE_VA",
                    "message": base_message,
                    "recommendation": (
                        "Ensure the virtual appliance is properly configured "
                        "to handle AKS traffic including: container image "
                        "pulls, Azure service connectivity, and API server "
                        "access. Consider adding specific routes for AKS "
                        "requirements."
                    ),
                })
            else:
                azure_va_routes = [
                    r
                    for r in va_routes
                    if (r.get("impact", {}).get("affected_traffic", []) and
                        "azure_services" in r.get("impact", {}).get(
                            "affected_traffic",
                            []))]
                if azure_va_routes:
                    route_names = [
                        r.get("name", "unnamed")
                        for r in azure_va_routes
                    ]
                    findings.append({
                        "severity": "warning",
                        "code": "UDR_AZURE_SERVICES_VA",
                        "message": (
                            f"Azure service traffic is routed through "
                            f"virtual appliance: {', '.join(route_names)}"
                        ),
                        "recommendation": (
                            "Verify the virtual appliance allows Azure "
                            "service connectivity or add specific routes "
                            "with nextHopType 'Internet' for required Azure "
                            "services."
                        ),
                    })

                mcr_va_routes = [
                    r
                    for r in va_routes
                    if (r.get("impact", {}).get("affected_traffic", []) and
                        "container_registry" in r.get("impact", {}).get(
                            "affected_traffic",
                            []))]
                if mcr_va_routes:
                    route_names = [
                        r.get("name", "unnamed")
                        for r in mcr_va_routes
                    ]
                    findings.append({
                        "severity": "warning",
                        "code": "UDR_CONTAINER_REGISTRY_VA",
                        "message": (
                            f"Container registry traffic is routed through "
                            f"virtual appliance: {', '.join(route_names)}"
                        ),
                        "recommendation": (
                            "Ensure the virtual appliance allows container "
                            "registry access or add specific routes for "
                            "Microsoft Container Registry (mcr.microsoft.com) "
                            "endpoints."
                        ),
                    })

        route_tables = udr_analysis.get("route_tables", [])
        bgp_disabled_tables = [
            rt for rt in route_tables
            if rt.get("disable_bgp_route_propagation") is True
        ]
        if bgp_disabled_tables:
            table_names = [
                rt.get("name", "unnamed")
                for rt in bgp_disabled_tables
            ]
            findings.append({
                "severity": "info",
                "code": "UDR_BGP_PROPAGATION_DISABLED",
                "message": (
                    f"BGP route propagation is disabled on route tables: "
                    f"{', '.join(table_names)}"
                ),
                "recommendation": (
                    "Consider the impact on connectivity if you have "
                    "ExpressRoute or VPN gateways that rely on BGP route "
                    "propagation."
                ),
            })

        if route_tables:
            total_routes = sum(
                len(rt.get("routes", []))
                for rt in route_tables
            )
            va_route_count = len(va_routes)
            critical_route_count = len(critical_routes)

            if total_routes > 0:
                outbound_type = outbound_analysis.get("type", "unknown")
                findings.append({
                    "severity": "info",
                    "code": "UDR_ANALYSIS_SUMMARY",
                    "message": (
                        f"UDR Analysis: Found {len(route_tables)} route "
                        f"table(s) with {total_routes} total routes on node "
                        f"subnets. {va_route_count} routes use virtual "
                        f"appliances, {critical_route_count} have high "
                        f"impact on connectivity. Cluster uses "
                        f"{outbound_type} outbound type."
                    ),
                    "recommendation": (
                        "Review the detailed UDR analysis in the JSON "
                        "report for specific route impacts and "
                        "recommendations."
                    ),
                })

    def _analyze_api_server_access_issues(
        self,
        api_server_access_analysis: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze API server access configuration issues"""
        if not api_server_access_analysis:
            return

        security_findings = api_server_access_analysis.get(
            "security_findings",
            []
        )
        for security_finding in security_findings:
            severity = security_finding.get("severity", "info")
            issue = security_finding.get("issue", "Unknown issue")
            description = security_finding.get("description", "")
            recommendation = security_finding.get("recommendation", "")
            range_info = security_finding.get("range", "")

            if "unrestricted access" in issue.lower():
                code = "API_UNRESTRICTED_ACCESS"
            elif "broad ip range" in issue.lower():
                code = "API_BROAD_IP_RANGE"
            elif "outbound ips not" in issue.lower():
                if "managednatgateway" in issue.lower():
                    code = "API_OUTBOUND_NATGW_INFO"
                else:
                    code = "API_OUTBOUND_NOT_AUTHORIZED"
            elif "invalid ip range" in issue.lower():
                code = "API_INVALID_IP_RANGE"
            elif "redundant configuration" in issue.lower():
                code = "API_REDUNDANT_CONFIG"
            elif "unrestricted public access" in issue.lower():
                code = "API_UNRESTRICTED_PUBLIC"
            else:
                code = "API_SECURITY_ISSUE"

            message = f"API server access: {issue}"
            if range_info:
                message += f" ({range_info})"
            if description:
                message += f" - {description}"

            findings.append({
                "severity": severity,
                "code": code,
                "message": message,
                "recommendation": recommendation
            })

        authorized_ranges = api_server_access_analysis.get(
            "authorized_ip_ranges",
            []
        )
        access_restrictions = api_server_access_analysis.get(
            "access_restrictions",
            {}
        )
        access_model = access_restrictions.get("model", "unknown")

        if access_model == "unrestricted_public" and not security_findings:
            findings.append({
                "severity": "info",
                "code": "API_PUBLIC_UNRESTRICTED",
                "message": (
                    "API server is publicly accessible without IP "
                    "restrictions"
                ),
                "recommendation": (
                    "Consider implementing authorized IP ranges or "
                    "converting to a private cluster for enhanced security"
                ),
            })
        elif access_model == "restricted_public":
            findings.append({
                "severity": "info",
                "code": "API_RESTRICTED_ACCESS",
                "message": (
                    f"API server access restricted to "
                    f"{len(authorized_ranges)} authorized IP range(s)"
                ),
                "recommendation": (
                    "Verify that all necessary IP ranges are included and "
                    "review ranges periodically"
                ),
            })

    def _analyze_nsg_issues(
        self,
        nsg_analysis: Dict[str, Any],
        findings: List[Dict[str, Any]],
        permission_findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze NSG configuration issues

        NOTE: NSG findings are created by nsg_analyzer.py. This method only adds
        informational findings that are not already created by the NSG analyzer.
        """
        if not nsg_analysis:
            return

        # NOTE: blocking_rules findings are already created by nsg_analyzer.py
        # in _analyze_nsg_compliance(), so we don't duplicate them here.

        # NOTE: inter_node_communication findings are already created by nsg_analyzer.py
        # in _analyze_inter_node_communication(), so we don't duplicate them here.

        # Only add informational finding if no NSGs found (not created by nsg_analyzer)
        # But don't add this finding if we couldn't check due to permission issues
        subnet_nsgs = nsg_analysis.get("subnet_nsgs", [])
        nic_nsgs = nsg_analysis.get("nic_nsgs", [])

        # Check if we have permission issues that prevented NSG analysis
        has_vnet_permission_issue = any(
            f.get("code") == "PERMISSION_INSUFFICIENT_VNET"
            for f in permission_findings
        )
        has_vmss_permission_issue = any(
            f.get("code") == "PERMISSION_INSUFFICIENT_VMSS"
            for f in permission_findings
        )

        # Only report "no NSGs" if we actually checked and found none
        # Don't report if we couldn't check due to permissions
        if (not subnet_nsgs and not nic_nsgs and
                not has_vnet_permission_issue and
                not has_vmss_permission_issue):
            findings.append({
                "severity": "info",
                "code": "NSG_NO_RESTRICTIONS",
                "message": "No NSGs found on cluster node subnets or NICs",
                "recommendation": (
                    "Consider implementing NSGs for enhanced network "
                    "security while ensuring AKS traffic is allowed"
                ),
            })

    def _analyze_connectivity_test_results(
        self,
        api_probe_results: Optional[Dict[str, Any]],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze connectivity test results and add findings"""
        if not api_probe_results:
            return

        if not api_probe_results.get("enabled"):
            return

        tests = api_probe_results.get("tests", [])

        failed_tests = [t for t in tests if t.get("status") == "failed"]
        error_tests = [t for t in tests if t.get("status") == "error"]

        dns_failures = [
            t for t in failed_tests
            if "DNS Resolution" in t.get("test_name", "")
        ]
        if dns_failures:
            dns_test_names = [t.get("test_name", "") for t in dns_failures]
            findings.append({
                "severity": "error",
                "code": "CONNECTIVITY_DNS_FAILURE",
                "message": (
                    f"DNS resolution tests failed: "
                    f"{', '.join(dns_test_names)}"
                ),
                "recommendation": (
                    "Check DNS server configuration and network "
                    "connectivity. Verify custom DNS servers are "
                    "accessible and properly configured."
                ),
            })

        http_failures = [
            t
            for t in failed_tests
            if any(
                keyword in t.get("test_name", "")
                for keyword in ["HTTP", "Connectivity", "curl"]
            )
        ]
        if http_failures:
            http_test_names = [t.get("test_name", "") for t in http_failures]
            findings.append({
                "severity": "error",
                "code": "CONNECTIVITY_HTTP_FAILURE",
                "message": (
                    f"HTTP connectivity tests failed: "
                    f"{', '.join(http_test_names)}"
                ),
                "recommendation": (
                    "Check outbound connectivity rules, firewall settings, "
                    "and network security groups. Verify internet access "
                    "from cluster nodes."
                ),
            })

        api_failures = [
            t for t in failed_tests
            if "API Server" in t.get("test_name", "")
        ]
        if api_failures:
            # Check if DNS tests passed - if so, it's likely firewall/NSG, not DNS
            dns_tests = [t for t in tests if "DNS Resolution" in t.get("test_name", "")]
            dns_passed = any(t.get("status") == "passed" for t in dns_tests)

            if dns_passed:
                # DNS works, so API server failure is likely firewall/NSG/outbound rules
                findings.append({
                    "severity": "critical",
                    "code": "CONNECTIVITY_API_SERVER_FAILURE",
                    "message": (
                        "API server connectivity test failed from cluster nodes"
                    ),
                    "recommendation": (
                        "Check outbound connectivity rules, firewall settings, and "
                        "network security groups. DNS resolution is working, so the "
                        "issue is likely with HTTPS connectivity (port 443) being "
                        "blocked. Verify API server IP is allowed in firewall/NSG rules."
                    ),
                })
            else:
                # DNS failed or no DNS test, use DNS-focused recommendation
                findings.append({
                    "severity": "critical",
                    "code": "CONNECTIVITY_API_SERVER_FAILURE",
                    "message": (
                        "API server connectivity test failed from cluster nodes"
                    ),
                    "recommendation": (
                        "Check private DNS configuration, VNet links, and API "
                        "server access policies. For private clusters, ensure "
                        "DNS resolution is working correctly."
                    ),
                })

        if error_tests:
            findings.append({
                "severity": "warning",
                "code": "CONNECTIVITY_TEST_ERRORS",
                "message": (
                    f"{len(error_tests)} connectivity tests could not be "
                    f"executed"
                ),
                "recommendation": (
                    "Check VMSS instance status and run-command "
                    "permissions. Ensure instances are running and "
                    "accessible."
                ),
            })

    def _parse_resource_id(self, resource_id: str) -> Dict[str, str]:
        """Parse Azure resource ID into components"""
        parts = {}
        if not resource_id:
            return parts

        segments = resource_id.split('/')
        if len(segments) < 9:
            return parts

        parts['subscription'] = segments[2] if len(segments) > 2 else ''
        parts['resource_group'] = segments[4] if len(segments) > 4 else ''

        return parts

    def _to_dict(self, obj: Any) -> Dict[str, Any]:
        """Convert object to dict with snake_case keys"""
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                # Convert camelCase to snake_case
                snake_key = ''.join(
                    ['_' + c.lower() if c.isupper() else c for c in key]
                ).lstrip('_')
                result[snake_key] = self._to_dict(value)
            return result
        if isinstance(obj, list):
            return [self._to_dict(item) for item in obj]
        return obj
