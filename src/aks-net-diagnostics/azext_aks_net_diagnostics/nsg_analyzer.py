"""
NSG Analyzer for AKS Network Diagnostics

This module analyzes Network Security Groups (NSGs) associated with AKS clusters,
checking for misconfigurations, blocking rules, and compliance with AKS requirements.
"""

from typing import Any, Dict, List, Optional, Set

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

from .base_analyzer import BaseAnalyzer
from .exceptions import AzureSDKError
from .models import Finding, FindingCode


# pylint: disable=too-many-instance-attributes
class NSGAnalyzer(BaseAnalyzer):
    """Analyzes Network Security Group configurations for AKS clusters."""

    def __init__(self, clients: Dict[str, Any], cluster_info: Dict[str, Any],
                 vmss_info: List[Dict[str, Any]], vm_info: Optional[List[Dict[str, Any]]] = None,
                 logger=None):
        """
        Initialize NSG Analyzer.

        Args:
            clients: Dictionary containing authenticated Azure clients
            cluster_info: AKS cluster information
            vmss_info: VMSS information from VMSS analyzer
            vm_info: VM information for Virtual Machines node pools
            logger: Optional logger instance
        """
        super().__init__(clients, cluster_info, logger=logger)
        self.vmss_info = vmss_info
        self.vm_info = vm_info or []
        self.network_client = clients.get('network_client')
        self.subscription_id = clients.get('subscription_id')
        self.nsg_analysis = {
            "subnet_nsgs": [],
            "nic_nsgs": [],
            "required_rules": [],
            "blocking_rules": [],
            "inter_node_communication": {"status": "unknown", "issues": []},
        }

    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive NSG analysis.

        Returns:
            Dictionary containing NSG analysis results
        """
        self.logger.info("Analyzing NSG configuration...")

        # Determine if cluster is private
        is_private_cluster = self._is_private_cluster()

        # Get required AKS rules
        required_rules = self._get_required_aks_rules(is_private_cluster)
        self.nsg_analysis["required_rules"] = required_rules

        # Analyze NSGs on subnets
        self._analyze_subnet_nsgs()

        # Analyze API server subnet NSG (for VNet integration)
        self._analyze_api_server_subnet_nsg()

        # Analyze NSGs on NICs
        self._analyze_nic_nsgs()

        # Check inter-node communication
        self._analyze_inter_node_communication()

        # Check Azure CNI Overlay pod CIDR rules (if applicable)
        self._check_overlay_pod_cidr_rules()

        # Check for blocking rules
        self._analyze_nsg_compliance()

        return self.nsg_analysis

    def _is_private_cluster(self) -> bool:
        """Check if cluster is private."""
        api_server_profile = self.cluster_info.get("api_server_access_profile")
        if api_server_profile:
            return api_server_profile.get("enable_private_cluster", False)
        return False

    def _is_vnet_integration_enabled(self) -> bool:
        """Check if API Server VNet Integration is enabled."""
        api_server_profile = self.cluster_info.get("api_server_access_profile")
        if not api_server_profile:
            return False

        # Check both top-level and additional_properties for backward compatibility
        if api_server_profile.get("enable_vnet_integration", False):
            return True
        additional_props = api_server_profile.get("additional_properties", {})
        return additional_props.get("enableVnetIntegration", False)

    def _get_api_server_subnet_id(self) -> Optional[str]:
        """Get the API server subnet ID for VNet integration clusters."""
        api_server_profile = self.cluster_info.get("api_server_access_profile")
        if not api_server_profile:
            return None
        return api_server_profile.get("subnet_id")

    def _get_required_aks_rules(self, is_private_cluster: bool) -> Dict[str, List[Dict[str, str]]]:
        """
        Get required NSG rules for AKS based on cluster type.

        Args:
            is_private_cluster: Whether the cluster is private

        Returns:
            Dictionary of required inbound and outbound rules
        """
        rules = {
            "outbound": [
                {
                    "name": "AKS_Registry_Access",
                    "protocol": "TCP",
                    "destination": "MicrosoftContainerRegistry",
                    "ports": ["443"],
                    "description": "Access to Microsoft Container Registry",
                },
                {
                    "name": "AKS_Azure_Management",
                    "protocol": "TCP",
                    "destination": "AzureCloud",
                    "ports": ["443"],
                    "description": "Azure management endpoints",
                },
                {
                    "name": "AKS_DNS",
                    "protocol": "UDP",
                    "destination": "*",
                    "ports": ["53"],
                    "description": "DNS resolution",
                },
                {
                    "name": "AKS_NTP",
                    "protocol": "UDP",
                    "destination": "*",
                    "ports": ["123"],
                    "description": "Network Time Protocol",
                },
            ],
            "inbound": [
                {
                    "name": "AKS_Inter_Node_Communication",
                    "protocol": "*",
                    "source": "VirtualNetwork",
                    "ports": ["*"],
                    "description": "Communication between cluster nodes",
                },
                {
                    "name": "AKS_Load_Balancer",
                    "protocol": "*",
                    "source": "AzureLoadBalancer",
                    "ports": ["*"],
                    "description": "Azure Load Balancer health probes",
                },
            ],
        }

        if not is_private_cluster:
            # Public clusters need API server access
            rules["outbound"].append(
                {
                    "name": "AKS_API_Server_Access",
                    "protocol": "TCP",
                    "destination": "*",
                    "ports": ["443"],
                    "description": "Access to AKS API server",
                }
            )

        return rules

    def _analyze_subnet_nsgs(self) -> None:
        """Analyze NSGs associated with node and pod subnets."""
        processed_subnets: Set[str] = set()

        # 1. Analyze node subnets from VMSS configuration
        for vmss in self.vmss_info:
            vm_profile = vmss.get("virtual_machine_profile", {})
            network_profile = vm_profile.get("network_profile", {})
            network_interfaces = network_profile.get("network_interface_configurations", [])

            for nic in network_interfaces:
                ip_configs = nic.get("ip_configurations", [])
                for ip_config in ip_configs:
                    subnet = ip_config.get("subnet", {})
                    subnet_id = subnet.get("id")

                    if not subnet_id or subnet_id in processed_subnets:
                        continue

                    processed_subnets.add(subnet_id)
                    self._process_subnet_nsg(subnet_id, subnet_type="node")

        # 1b. Analyze node subnets from VM configuration (for Virtual Machines node pools)
        for vm in self.vm_info:
            # Get NIC details we stored during collection
            nic_details_list = vm.get("nic_details", [])
            for nic_detail in nic_details_list:
                ip_configs = nic_detail.get("ip_configurations", [])
                for ip_config in ip_configs:
                    subnet = ip_config.get("subnet", {})
                    subnet_id = subnet.get("id")

                    if not subnet_id or subnet_id in processed_subnets:
                        continue

                    processed_subnets.add(subnet_id)
                    self._process_subnet_nsg(subnet_id, subnet_type="node")

        # 2. Analyze pod subnets from agent pool configuration (Azure CNI Pod Subnet mode)
        agent_pools = self.cluster_info.get("agent_pool_profiles", [])
        if not agent_pools:
            # Try alternative field name
            agent_pools = self.cluster_info.get("agentPoolProfiles", [])

        for pool in agent_pools:
            pod_subnet_id = pool.get("pod_subnet_id") or pool.get("podSubnetId")
            if pod_subnet_id and pod_subnet_id not in processed_subnets:
                processed_subnets.add(pod_subnet_id)
                pool_name = pool.get("name", "unknown")
                self.logger.info("  Analyzing pod subnet NSG for pool '%s'", pool_name)
                self._process_subnet_nsg(pod_subnet_id, subnet_type="pod")

    def _process_subnet_nsg(self, subnet_id: str, subnet_type: str = "node") -> None:
        """
        Process NSG for a single subnet.

        Args:
            subnet_id: Azure resource ID of the subnet
            subnet_type: Type of subnet ('node' or 'pod')
        """
        try:
            # Parse subnet ID to get components
            parsed = self._parse_resource_id(subnet_id)
            subnet_rg = parsed["resource_group"]
            vnet_name = parsed["parent_name"]  # VNet is parent of subnet
            subnet_name = parsed["resource_name"]

            # Get subnet info using SDK
            subnet_info = self.network_client.subnets.get(subnet_rg, vnet_name, subnet_name)

            nsg_info = subnet_info.network_security_group
            if nsg_info:
                nsg_id = nsg_info.id
                nsg_name = nsg_id.split("/")[-1] if nsg_id else "unknown"

                # Parse NSG ID to get resource group
                nsg_parsed = self._parse_resource_id(nsg_id)
                nsg_rg = nsg_parsed["resource_group"]

                # Get NSG details using SDK
                nsg_details = self.network_client.network_security_groups.get(nsg_rg, nsg_name)

                if nsg_details:
                    # Convert to dictionary with snake_case keys
                    nsg_dict = self._to_dict(nsg_details)

                    self.nsg_analysis["subnet_nsgs"].append(
                        {
                            "subnet_id": subnet_id,
                            "subnet_name": subnet_info.name,
                            "subnet_type": subnet_type,  # Track whether this is node or pod subnet
                            "nsg_id": nsg_id,
                            "nsg_name": nsg_name,
                            "rules": nsg_dict.get("security_rules", []),
                            "default_rules": nsg_dict.get("default_security_rules", []),
                        }
                    )

                    self.logger.info(
                        "  Found NSG on %s subnet %s: %s",
                        subnet_type,
                        subnet_info.name,
                        nsg_name
                    )
            else:
                self.logger.info(
                    "  No NSG found on %s subnet %s",
                    subnet_type,
                    subnet_info.name
                )

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.error("  Failed to analyze subnet %s: %s", subnet_id, e)
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error("  Error parsing subnet ID %s: %s", subnet_id, e)

    def _analyze_api_server_subnet_nsg(self) -> None:
        """Analyze NSG on API server subnet for VNet integration clusters."""
        if not self._is_vnet_integration_enabled():
            self.logger.debug("  VNet integration not enabled, skipping API server subnet NSG analysis")
            return

        api_server_subnet_id = self._get_api_server_subnet_id()
        if not api_server_subnet_id:
            self.logger.warning("  VNet integration enabled but no API server subnet ID found")
            return

        self.logger.info("  Analyzing API server subnet NSG for VNet integration")

        try:
            # Parse subnet ID to get components
            parsed = self._parse_resource_id(api_server_subnet_id)
            subnet_rg = parsed["resource_group"]
            vnet_name = parsed["parent_name"]
            subnet_name = parsed["resource_name"]

            # Get subnet info
            subnet_info = self.network_client.subnets.get(subnet_rg, vnet_name, subnet_name)

            nsg_info = subnet_info.network_security_group
            if nsg_info:
                nsg_id = nsg_info.id
                nsg_name = nsg_id.split("/")[-1] if nsg_id else "unknown"

                # Parse NSG ID to get resource group
                nsg_parsed = self._parse_resource_id(nsg_id)
                nsg_rg = nsg_parsed["resource_group"]

                # Get NSG details
                nsg_details = self.network_client.network_security_groups.get(nsg_rg, nsg_name)

                if nsg_details:
                    # Convert to dictionary
                    nsg_dict = self._to_dict(nsg_details)

                    # Add to subnet NSGs with special type
                    self.nsg_analysis["subnet_nsgs"].append(
                        {
                            "subnet_id": api_server_subnet_id,
                            "subnet_name": subnet_info.name,
                            "subnet_type": "api_server",  # Special type for API server subnet
                            "nsg_id": nsg_id,
                            "nsg_name": nsg_name,
                            "rules": nsg_dict.get("security_rules", []),
                            "default_rules": nsg_dict.get("default_security_rules", []),
                        }
                    )

                    self.logger.info("  Found NSG on API server subnet %s: %s", subnet_info.name, nsg_name)

                    # Check for critical VNet integration rules
                    self._check_vnet_integration_nsg_rules(nsg_dict, subnet_info.name)
            else:
                self.logger.info("  No NSG found on API server subnet %s", subnet_info.name)

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.error("  Failed to analyze API server subnet %s: %s", api_server_subnet_id, e)
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error("  Error analyzing API server subnet: %s", e)

    def _analyze_nic_nsgs(self) -> None:
        """Analyze NSGs associated with node NICs."""
        # Analyze VMSS NICs
        for vmss in self.vmss_info:
            vmss_name = vmss.get("name")
            if not vmss_name:
                continue

            vm_profile = vmss.get("virtual_machine_profile", {})
            network_profile = vm_profile.get("network_profile", {})
            network_interfaces = network_profile.get("network_interface_configurations", [])

            for nic_config in network_interfaces:
                nsg_info = nic_config.get("network_security_group")
                if nsg_info:
                    nsg_id = nsg_info.get("id")
                    nsg_name = nsg_id.split("/")[-1] if nsg_id else "unknown"

                    try:
                        # Parse NSG ID to get resource group
                        nsg_parsed = self._parse_resource_id(nsg_id)
                        nsg_rg = nsg_parsed["resource_group"]

                        # Get NSG details using SDK
                        nsg_details = self.network_client.network_security_groups.get(nsg_rg, nsg_name)

                        if nsg_details:
                            # Convert to dictionary with snake_case keys
                            nsg_dict = self._to_dict(nsg_details)

                            self.nsg_analysis["nic_nsgs"].append(
                                {
                                    "vmss_name": vmss_name,
                                    "nic_name": nic_config.get("name", "unknown"),
                                    "nsg_id": nsg_id,
                                    "nsg_name": nsg_name,
                                    "rules": nsg_dict.get("security_rules", []),
                                    "default_rules": nsg_dict.get("default_security_rules", []),
                                }
                            )

                            self.logger.info("  Found NSG on VMSS %s NIC: %s", vmss_name, nsg_name)

                    except (AzureSDKError, HttpResponseError) as e:
                        self.logger.error("  Failed to analyze NIC NSG %s: %s", nsg_id, e)
                else:
                    self.logger.info("  No NSG found on VMSS %s NIC", vmss_name)

        # Analyze VM NICs (for Virtual Machines node pools)
        for vm in self.vm_info:
            vm_name = vm.get("name")
            if not vm_name:
                continue

            # Get NIC details we stored during collection
            nic_details_list = vm.get("nic_details", [])
            for nic_detail in nic_details_list:
                nsg_info = nic_detail.get("network_security_group")
                if nsg_info:
                    nsg_id = nsg_info.get("id")
                    nsg_name = nsg_id.split("/")[-1] if nsg_id else "unknown"

                    try:
                        # Parse NSG ID to get resource group
                        nsg_parsed = self._parse_resource_id(nsg_id)
                        nsg_rg = nsg_parsed["resource_group"]

                        # Get NSG details using SDK
                        nsg_details = self.network_client.network_security_groups.get(nsg_rg, nsg_name)

                        if nsg_details:
                            # Convert to dictionary with snake_case keys
                            nsg_dict = self._to_dict(nsg_details)

                            self.nsg_analysis["nic_nsgs"].append(
                                {
                                    "vm_name": vm_name,
                                    "nic_name": nic_detail.get("name", "unknown"),
                                    "nsg_id": nsg_id,
                                    "nsg_name": nsg_name,
                                    "rules": nsg_dict.get("security_rules", []),
                                    "default_rules": nsg_dict.get("default_security_rules", []),
                                }
                            )

                            self.logger.info("  Found NSG on VM %s NIC: %s", vm_name, nsg_name)

                    except (AzureSDKError, HttpResponseError) as e:
                        self.logger.error("  Failed to analyze NIC NSG %s: %s", nsg_id, e)
                else:
                    self.logger.info("  No NSG found on VM %s NIC", vm_name)

    def _analyze_inter_node_communication(self) -> None:
        """Analyze if NSG rules could block inter-node communication."""
        all_nsgs = self.nsg_analysis["subnet_nsgs"] + self.nsg_analysis["nic_nsgs"]
        issues = []

        for nsg in all_nsgs:
            blocking_rules = []
            all_rules = nsg.get("rules", []) + nsg.get("default_rules", [])

            for rule in all_rules:
                if (rule.get("access", "").lower() == "deny" and
                        rule.get("direction", "").lower() == "inbound" and
                        rule.get("priority", 0) < 65000):

                    source = rule.get("source_address_prefix", "")
                    if self._is_vnet_source(source):
                        blocking_rules.append(
                            {
                                "rule_name": rule.get("name", "unknown"),
                                "priority": rule.get("priority", 0),
                                "source": source,
                                "destination": rule.get("destination_address_prefix", ""),
                                "protocol": rule.get("protocol", ""),
                                "ports": rule.get("destination_port_range", ""),
                            }
                        )

            if blocking_rules:
                issues.append(
                    {
                        "nsg_name": nsg.get("nsg_name"),
                        "location": "subnet" if "subnet_id" in nsg else "nic",
                        "blocking_rules": blocking_rules,
                    }
                )

        self.nsg_analysis["inter_node_communication"] = {
            "status": "potential_issues" if issues else "ok",
            "issues": issues,
        }

        if issues:
            for issue in issues:
                self.add_finding(
                    Finding.create_warning(
                        FindingCode.NSG_INTER_NODE_BLOCKED,
                        message=f"NSG '{issue['nsg_name']}' has rules that may block inter-node communication",
                        recommendation=f"Review blocking rules in NSG on {issue['location']}",
                        nsg_name=issue["nsg_name"],
                        blocking_rules=issue["blocking_rules"],
                    )
                )

    def _check_overlay_pod_cidr_rules(self) -> None:
        """
        Check NSG rules for Azure CNI Overlay pod CIDR traffic.

        Azure CNI Overlay has no encapsulation, so NSG rules must allow:
        - Node CIDR to Pod CIDR (for service routing)
        - Pod CIDR to Pod CIDR (for pod-to-pod communication, DNS)

        Reference: https://learn.microsoft.com/en-us/azure/aks/azure-cni-overlay#network-security-groups
        """
        # Check if this is Azure CNI Overlay mode
        network_profile = self.cluster_info.get("network_profile", {})
        network_plugin = network_profile.get("network_plugin")
        network_plugin_mode = network_profile.get("network_plugin_mode")
        pod_cidr = network_profile.get("pod_cidr")

        # Only check for Azure CNI in overlay mode
        if network_plugin != "azure" or network_plugin_mode != "overlay":
            self.logger.debug(
                "Skipping overlay pod CIDR checks - not Azure CNI Overlay mode "
                "(plugin=%s, mode=%s)",
                network_plugin,
                network_plugin_mode
            )
            return

        if not pod_cidr:
            self.logger.warning(
                "Azure CNI Overlay detected but pod CIDR not found in network profile"
            )
            return

        self.logger.info("Checking NSG rules for Azure CNI Overlay pod CIDR: %s", pod_cidr)

        # Get node CIDR from VNet subnets
        node_cidr = self._get_node_cidr()
        if not node_cidr:
            self.logger.warning("Could not determine node CIDR for overlay validation")
            return

        # Check all NSGs
        all_nsgs = self.nsg_analysis["subnet_nsgs"] + self.nsg_analysis["nic_nsgs"]
        blocking_issues = []

        for nsg in all_nsgs:
            nsg_name = nsg.get("nsg_name", "unknown")
            all_rules = nsg.get("rules", []) + nsg.get("default_rules", [])

            # Check for rules blocking Node → Pod CIDR
            node_to_pod_blocked = self._check_cidr_traffic_blocked(
                all_rules, node_cidr, pod_cidr, "Node-to-Pod"
            )

            # Check for rules blocking Pod → Pod CIDR
            pod_to_pod_blocked = self._check_cidr_traffic_blocked(
                all_rules, pod_cidr, pod_cidr, "Pod-to-Pod"
            )

            if node_to_pod_blocked or pod_to_pod_blocked:
                blocking_issues.append({
                    "nsg_name": nsg_name,
                    "node_to_pod_blocked": node_to_pod_blocked,
                    "pod_to_pod_blocked": pod_to_pod_blocked,
                    "node_cidr": node_cidr,
                    "pod_cidr": pod_cidr
                })

        # Create findings for any blocking issues
        if blocking_issues:
            for issue in blocking_issues:
                blocked_types = []
                if issue["node_to_pod_blocked"]:
                    blocked_types.append("Node→Pod")
                if issue["pod_to_pod_blocked"]:
                    blocked_types.append("Pod→Pod")

                traffic_types = " and ".join(blocked_types)
                severity = FindingCode.NSG_POD_CIDR_BLOCKED
                message = (
                    f"NSG '{issue['nsg_name']}' may block Azure CNI Overlay pod traffic ({traffic_types})"
                )
                recommendation = (
                    f"Azure CNI Overlay requires NSG rules to allow:\n"
                    f"  - Node CIDR ({issue['node_cidr']}) → Pod CIDR ({issue['pod_cidr']}) for service routing\n"
                    f"  - Pod CIDR ({issue['pod_cidr']}) → Pod CIDR ({issue['pod_cidr']}) for pod-to-pod, DNS\n"
                    f"Review and add NSG rules to allow this traffic. "
                    f"See: https://learn.microsoft.com/en-us/azure/aks/azure-cni-overlay#network-security-groups"
                )

                self.add_finding(
                    Finding.create_warning(
                        severity,
                        message=message,
                        recommendation=recommendation,
                        nsg_name=issue["nsg_name"],
                        node_cidr=issue["node_cidr"],
                        pod_cidr=issue["pod_cidr"],
                        blocked_traffic=traffic_types
                    )
                )

    def _get_node_cidr(self) -> Optional[str]:
        """Get node CIDR from cluster agent pool subnet configuration."""
        # Try to get from VMSS info first
        if self.vmss_info:
            for vmss in self.vmss_info:
                subnets = vmss.get("subnets", [])
                if subnets and len(subnets) > 0:
                    # Return the first subnet's address prefix
                    address_prefix = subnets[0].get("address_prefix")
                    if address_prefix:
                        self.logger.debug("Found node CIDR from VMSS: %s", address_prefix)
                        return address_prefix

        # Fallback: get subnet ID from agent pools and query it
        agent_pools = self.cluster_info.get("agent_pool_profiles", [])
        if not agent_pools:
            # Try alternative field name
            agent_pools = self.cluster_info.get("agentPoolProfiles", [])

        for pool in agent_pools:
            subnet_id = pool.get("vnet_subnet_id") or pool.get("vnetSubnetId")
            if subnet_id and subnet_id != "null" and self.network_client:
                try:
                    # Parse subnet ID to get resource info
                    # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/
                    # Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}
                    parts = subnet_id.split("/")
                    if len(parts) >= 11:
                        resource_group = parts[4]
                        vnet_name = parts[8]
                        subnet_name = parts[10]

                        # Query the subnet
                        subnet = self.network_client.subnets.get(
                            resource_group,
                            vnet_name,
                            subnet_name
                        )

                        if subnet and hasattr(subnet, 'address_prefix'):
                            address_prefix = subnet.address_prefix
                            self.logger.debug(
                                "Found node CIDR from agent pool subnet: %s",
                                address_prefix
                            )
                            return address_prefix

                except Exception as e:  # pylint: disable=broad-except
                    self.logger.debug("Failed to query subnet %s: %s", subnet_id, e)
                    continue

        self.logger.debug("Could not determine node CIDR from any source")
        return None

    def _check_cidr_traffic_blocked(
        self,
        rules: List[Dict[str, Any]],
        source_cidr: str,
        dest_cidr: str,
        traffic_type: str
    ) -> bool:
        """
        Check if NSG rules block traffic between two CIDR ranges.

        Args:
            rules: List of NSG rules
            source_cidr: Source CIDR range
            dest_cidr: Destination CIDR range
            traffic_type: Description of traffic type (for logging)

        Returns:
            True if traffic appears to be blocked
        """
        # Sort rules by priority
        sorted_rules = sorted(rules, key=lambda x: x.get("priority", 65000))

        for rule in sorted_rules:
            if rule.get("access", "").lower() == "deny":
                # Check if this deny rule matches our traffic
                source_match = self._cidr_matches_rule_prefix(
                    source_cidr, rule.get("source_address_prefix", "")
                )
                dest_match = self._cidr_matches_rule_prefix(
                    dest_cidr, rule.get("destination_address_prefix", "")
                )

                if source_match and dest_match:
                    self.logger.info(
                        "  Found deny rule blocking %s traffic: %s (priority %s)",
                        traffic_type,
                        rule.get("name"),
                        rule.get("priority")
                    )
                    return True

            elif rule.get("access", "").lower() == "allow":
                # Allow rule matched, traffic is permitted
                source_match = self._cidr_matches_rule_prefix(
                    source_cidr, rule.get("source_address_prefix", "")
                )
                dest_match = self._cidr_matches_rule_prefix(
                    dest_cidr, rule.get("destination_address_prefix", "")
                )

                if source_match and dest_match:
                    self.logger.debug(
                        "  Found allow rule permitting %s traffic: %s",
                        traffic_type,
                        rule.get("name")
                    )
                    return False

        # No explicit allow or deny found - check default rules
        # Default VirtualNetwork rules typically allow intra-VNet traffic
        return False

    def _cidr_matches_rule_prefix(self, cidr: str, rule_prefix: str) -> bool:
        """
        Check if a CIDR range matches an NSG rule address prefix.

        Args:
            cidr: CIDR range to check (e.g., "10.244.0.0/16")
            rule_prefix: NSG rule address prefix (e.g., "*", "VirtualNetwork", "10.0.0.0/8")

        Returns:
            True if the CIDR could match the rule prefix
        """
        if not rule_prefix or not cidr:
            return False

        # Wildcard matches everything
        if rule_prefix == "*":
            return True

        # VirtualNetwork service tag matches private IP ranges
        if rule_prefix == "VirtualNetwork":
            return self._is_private_ip_range(cidr)

        # Exact match
        if cidr == rule_prefix:
            return True

        # Check if CIDR is within rule prefix range (simplified check)
        # For proper implementation, would need IP address library
        # For now, check if they share the same network prefix
        cidr_network = cidr.split("/")[0].split(".")[0]
        rule_network = rule_prefix.split("/")[0].split(".")[0]

        return cidr_network == rule_network

    def _is_private_ip_range(self, cidr: str) -> bool:
        """Check if CIDR is in private IP range."""
        if not cidr:
            return False

        first_octet = cidr.split(".")[0]
        return first_octet in ["10", "172", "192"]

    def _is_vnet_source(self, source: str) -> bool:
        """Check if source is VirtualNetwork or private IP range."""
        if source in ["*", "VirtualNetwork"]:
            return True
        # Check for private IP ranges
        if source.startswith("10.") or source.startswith("192.168.") or source.startswith("172."):
            return True
        return False

    def _check_vnet_integration_nsg_rules(self, nsg_dict: Dict[str, Any], subnet_name: str) -> None:
        """
        Check NSG rules on API server subnet for VNet integration clusters.

        Critical rules to check:
        1. Outbound from cluster subnet to API server subnet on port 443 (node-to-API communication)
        2. Inbound to cluster subnet from API server subnet on port 10250 (API-to-node for kubectl exec/logs)

        Args:
            nsg_dict: NSG configuration dictionary
            subnet_name: Name of the API server subnet
        """
        all_rules = nsg_dict.get("security_rules", []) + nsg_dict.get("default_rules", [])
        sorted_rules = sorted(all_rules, key=lambda x: x.get("priority", 65000))

        # Check for rules that might block critical VNet integration traffic
        blocking_issues = []

        for rule in sorted_rules:
            if rule.get("access", "").lower() == "deny":
                direction = rule.get("direction", "").lower()
                protocol = rule.get("protocol", "").upper()
                dest_port = rule.get("destination_port_range", "")

                # Check if blocks port 443 outbound (node-to-API communication)
                if direction == "outbound" and protocol in ["TCP", "*"]:
                    if self._port_in_range(443, dest_port):
                        blocking_issues.append({
                            "rule_name": rule.get("name", "unknown"),
                            "priority": rule.get("priority", 0),
                            "issue": "Blocks outbound HTTPS (port 443) from API server subnet",
                            "impact": "May prevent nodes from communicating with API server",
                            "recommendation": (
                                "Ensure outbound TCP 443 is allowed from cluster "
                                "subnet to API server subnet"
                            ),
                        })

                # Check if blocks port 10250 inbound (API-to-node for kubectl exec/logs)
                if direction == "inbound" and protocol in ["TCP", "*"]:
                    if self._port_in_range(10250, dest_port):
                        blocking_issues.append({
                            "rule_name": rule.get("name", "unknown"),
                            "priority": rule.get("priority", 0),
                            "issue": "Blocks inbound TCP 10250 to cluster nodes",
                            "impact": "kubectl exec, kubectl logs, and run command functionality will fail",
                            "recommendation": (
                                "Ensure inbound TCP 10250 is allowed from API server "
                                "subnet to cluster subnet"
                            ),
                        })

        # Add findings for blocking rules
        nsg_name = nsg_dict.get("name", subnet_name)
        for issue in blocking_issues:
            self.add_finding(
                Finding.create_critical(
                    FindingCode.NSG_BLOCKING_AKS_TRAFFIC,
                    message=f"NSG rule '{issue['rule_name']}' in '{nsg_name}' on API server subnet "
                            f"may block VNet integration traffic",
                    recommendation=issue['recommendation'],
                    rule_name=issue['rule_name'],
                    priority=issue['priority'],
                    issue=issue['issue'],
                    impact=issue['impact'],
                    subnet_type="api_server",
                )
            )

        if not blocking_issues:
            self.logger.debug("    [OK] No blocking rules found on API server subnet NSG")

    def _port_in_range(self, port: int, port_range: str) -> bool:
        """
        Check if a specific port is included in a port range.

        Args:
            port: Port number to check
            port_range: Port range string (e.g., "443", "80-443", "*")

        Returns:
            True if port is in range, False otherwise
        """
        if not port_range or port_range == "*":
            return True

        # Single port
        if "-" not in str(port_range):
            try:
                return int(port_range) == port
            except ValueError:
                return False

        # Port range
        try:
            start, end = port_range.split("-")
            return int(start) <= port <= int(end)
        except (ValueError, AttributeError):
            return False

    # pylint: disable=too-many-nested-blocks
    def _analyze_nsg_compliance(self) -> None:
        """Analyze NSG compliance with AKS requirements."""
        all_nsgs = self.nsg_analysis["subnet_nsgs"] + self.nsg_analysis["nic_nsgs"]
        blocking_rules = []

        for nsg in all_nsgs:
            nsg_name = nsg.get("nsg_name", "unknown")
            all_rules = nsg.get("rules", []) + nsg.get("default_rules", [])

            # Sort by priority
            sorted_rules = sorted(all_rules, key=lambda x: x.get("priority", 65000))

            # Check for rules that might block AKS traffic
            for rule in sorted_rules:
                if rule.get("access", "").lower() == "deny" and rule.get("priority", 0) < 65000:
                    if rule.get("direction", "").lower() == "outbound":
                        dest = rule.get("destination_address_prefix", "")
                        ports = rule.get("destination_port_range", "")
                        protocol = rule.get("protocol", "")

                        # Check if blocks essential AKS traffic
                        if self._blocks_aks_traffic(dest, ports, protocol):
                            is_overridden, overriding_rules = self._check_rule_precedence(rule, sorted_rules)

                            blocking_rule = {
                                "nsg_name": nsg_name,
                                "rule_name": rule.get("name", "unknown"),
                                "priority": rule.get("priority", 0),
                                "direction": rule.get("direction", ""),
                                "protocol": protocol,
                                "destination": dest,
                                "ports": ports,
                                "impact": "Could block AKS management traffic",
                                "is_overridden": is_overridden,
                                "overridden_by": overriding_rules,
                                "effective_severity": "warning" if is_overridden else "critical",
                            }

                            blocking_rules.append(blocking_rule)

                            # Add finding
                            if is_overridden:
                                self.add_finding(
                                    Finding.create_warning(
                                        FindingCode.NSG_POTENTIAL_BLOCK,
                                        message=f"NSG rule '{rule.get('name')}' in '{nsg_name}' "
                                                f"may block AKS traffic but is overridden",
                                        recommendation="Verify that override rules are correctly configured",
                                        **blocking_rule,
                                    )
                                )
                            else:
                                self.add_finding(
                                    Finding.create_critical(
                                        FindingCode.NSG_BLOCKING_AKS_TRAFFIC,
                                        message=f"NSG rule '{rule.get('name')}' in '{nsg_name}' "
                                                f"may block AKS traffic",
                                        recommendation=f"Review NSG rule priority {rule.get('priority')} - "
                                                       f"Could block AKS management traffic",
                                        **blocking_rule,
                                    )
                                )

        self.nsg_analysis["blocking_rules"] = blocking_rules

    def _blocks_aks_traffic(self, dest: str, ports: str, protocol: str) -> bool:
        """Check if rule blocks essential AKS traffic."""
        # Check destination
        if dest in ["*", "Internet"] or "MicrosoftContainerRegistry" in str(dest) or "AzureCloud" in str(dest):
            # Check ports and protocol
            if ("443" in str(ports) or "*" in str(ports)) and protocol.upper() in ["TCP", "*"]:
                return True
        return False

    def _check_rule_precedence(
        self, deny_rule: Dict[str, Any], sorted_rules: List[Dict[str, Any]]
    ) -> tuple:
        """
        Check if a deny rule is overridden by higher priority allow rules.

        Args:
            deny_rule: The deny rule to check
            sorted_rules: All rules sorted by priority

        Returns:
            Tuple of (is_overridden, overriding_rules)
        """
        deny_priority = deny_rule.get("priority", 65000)
        overriding_rules = []

        for rule in sorted_rules:
            rule_priority = rule.get("priority", 65000)

            if rule_priority >= deny_priority:
                break

            if (rule.get("access", "").lower() == "allow" and
                    rule.get("direction", "").lower() == deny_rule.get("direction", "").lower()):

                if self._rules_overlap(deny_rule, rule):
                    overriding_rules.append(
                        {
                            "rule_name": rule.get("name", "unknown"),
                            "priority": rule_priority,
                            "destination": rule.get("destination_address_prefix", ""),
                            "ports": rule.get("destination_port_range", ""),
                            "protocol": rule.get("protocol", ""),
                        }
                    )

        return len(overriding_rules) > 0, overriding_rules

    def _rules_overlap(self, deny_rule: Dict[str, Any], allow_rule: Dict[str, Any]) -> bool:
        """
        Check if an allow rule overlaps with a deny rule for AKS traffic.

        This method properly validates that the allow rule actually covers
        the specific traffic that AKS needs.
        """
        # Check destination overlap with proper service tag semantics
        deny_dest = deny_rule.get("destination_address_prefix", "").lower()
        allow_dest = allow_rule.get("destination_address_prefix", "").lower()

        dest_overlap = False

        # Allow rule with '*' covers everything
        if allow_dest == "*":
            dest_overlap = True
        # Allow rule with same destination as deny
        elif allow_dest == deny_dest:
            dest_overlap = True
        # Special case: Internet traffic requirements
        elif deny_dest == "internet":
            # For Internet-blocking rules, only these service tags actually help:
            # - Internet (explicit allow)
            # - AzureContainerRegistry (covers MCR)
            # - * (covers everything)
            # NOTE: AzureCloud does NOT cover general Internet destinations like MCR
            if allow_dest in ["internet", "azurecontainerregistry"]:
                dest_overlap = True
        # If deny is wildcard, allow must also be wildcard
        elif deny_dest == "*":
            if allow_dest in ["*", "internet", "azurecloud", "azurecontainerregistry"]:
                dest_overlap = True
        # AzureCloud covers Azure-specific services but not general Internet
        elif deny_dest in ["azurecloud", "microsoftcontainerregistry", "azurecontainerregistry"]:
            if allow_dest in ["*", "azurecloud", "azurecontainerregistry"]:
                dest_overlap = True

        if not dest_overlap:
            return False

        # Check port overlap
        deny_ports = str(deny_rule.get("destination_port_range", "")).lower()
        allow_ports = str(allow_rule.get("destination_port_range", "")).lower()

        port_overlap = False
        if allow_ports == "*" or deny_ports == "*":
            port_overlap = True
        elif "443" in deny_ports and ("443" in allow_ports or "*" in allow_ports):
            port_overlap = True
        elif deny_ports == allow_ports:
            port_overlap = True

        if not port_overlap:
            return False

        # Check protocol overlap
        deny_protocol = deny_rule.get("protocol", "").upper()
        allow_protocol = allow_rule.get("protocol", "").upper()

        protocol_overlap = (allow_protocol == "*" or
                            deny_protocol == "*" or
                            deny_protocol == allow_protocol or
                            (deny_protocol in ["TCP", "*"] and allow_protocol in ["TCP", "*"]))

        return protocol_overlap

    def _parse_resource_id(self, resource_id: str) -> Dict[str, str]:
        """
        Parse Azure resource ID into components.

        Args:
            resource_id: Azure resource ID string

        Returns:
            Dictionary with parsed components
        """
        parts = resource_id.split('/')
        result = {}

        # Extract subscription and resource group
        for i, part in enumerate(parts):
            if part.lower() == 'subscriptions' and i + 1 < len(parts):
                result['subscription'] = parts[i + 1]
            elif part.lower() == 'resourcegroups' and i + 1 < len(parts):
                result['resource_group'] = parts[i + 1]
            elif part.lower() == 'providers' and i + 1 < len(parts):
                result['provider'] = parts[i + 1]

        # Extract resource types and names after provider
        # Format: /providers/{provider}/{type1}/{name1}/{type2}/{name2}/...
        provider_index = -1
        for i, part in enumerate(parts):
            if part.lower() == 'providers':
                provider_index = i
                break

        if provider_index >= 0 and provider_index + 2 < len(parts):
            # Skip provider namespace, start with first resource type/name pair
            resource_parts = parts[provider_index + 2:]

            # Process resource type/name pairs
            for i in range(0, len(resource_parts) - 1, 2):
                resource_type = resource_parts[i]
                resource_name = resource_parts[i + 1]

                # First pair is parent (e.g., virtualNetworks)
                # Last pair is the actual resource (e.g., subnets)
                if i == 0 and len(resource_parts) > 2:
                    result['parent_type'] = resource_type
                    result['parent_name'] = resource_name
                elif i == len(resource_parts) - 2:
                    result['resource_type'] = resource_type
                    result['resource_name'] = resource_name

            # Handle simple resources without parent (only one type/name pair)
            if 'resource_name' not in result and 'parent_name' in result:
                result['resource_type'] = result.get('parent_type', '')
                result['resource_name'] = result.get('parent_name', '')
                result.pop('parent_type', None)
                result.pop('parent_name', None)

        return result

    def _to_dict(self, obj: Any) -> Dict[str, Any]:
        """
        Convert SDK object to dictionary with snake_case keys.

        Args:
            obj: Azure SDK object

        Returns:
            Dictionary representation with snake_case keys
        """
        if hasattr(obj, 'as_dict'):
            result = obj.as_dict()
        elif isinstance(obj, dict):
            result = obj
        else:
            return {}

        # Convert all keys to snake_case
        def to_snake_case(name: str) -> str:
            """Convert camelCase to snake_case."""
            import re
            name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
            return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()

        def convert_dict(d: Dict) -> Dict:
            """Recursively convert dict keys to snake_case."""
            if not isinstance(d, dict):
                return d
            return {
                to_snake_case(k): convert_dict(v) if isinstance(v, dict)
                else [convert_dict(i) if isinstance(i, dict) else i for i in v] if isinstance(v, list)
                else v
                for k, v in d.items()
            }

        return convert_dict(result)
