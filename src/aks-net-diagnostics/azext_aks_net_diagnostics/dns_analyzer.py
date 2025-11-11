# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
DNS Analyzer for AKS Network Diagnostics

This module analyzes DNS configuration for AKS clusters, including:
- Private DNS zone configuration
- DNS resolution validation
- Private IP validation for private clusters

Adapted for Azure CLI - uses pre-authenticated SDK clients.
"""

import ipaddress
import re
from typing import Any, Dict, List

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

from .base_analyzer import BaseAnalyzer
from .models import Finding, FindingCode, Severity


class DNSAnalyzer(BaseAnalyzer):
    """Analyzer for AKS DNS configuration and resolution"""

    def __init__(self, clients: Dict[str, Any], cluster_info: Dict[str, Any], logger=None):
        """
        Initialize DNS analyzer

        Args:
            clients: Dictionary of pre-authenticated Azure SDK clients
            cluster_info: AKS cluster information
            logger: Optional logger instance
        """
        super().__init__(clients, cluster_info, logger=logger)
        self.dns_analysis: Dict[str, Any] = {}
        self.vnet_dns_servers: List[str] = []

    def _check_authorization_error(
        self,
        error: HttpResponseError,
        resource_type: str,
        resource_name: str,
        resource_group: str
    ) -> bool:
        """
        Check if the error is an authorization failure and create a finding.

        Args:
            error: The HttpResponseError to check
            resource_type: Type of resource (e.g., 'VNet')
            resource_name: Name of the resource
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

            # Create finding (use existing VNet permission code)
            finding = Finding(
                severity=Severity.WARNING,
                code=FindingCode.PERMISSION_INSUFFICIENT_VNET,
                message=f"Incomplete DNS/VNet Analysis - Missing permission to read {resource_name}",
                recommendation=recommendation,
                details={
                    'resource_type': resource_type,
                    'resource_name': resource_name,
                    'resource_group': resource_group,
                    'missing_permission': missing_permission,
                    'error': error_message,
                    'context': 'DNS analysis'
                }
            )
            self.add_finding(finding)
            return True

        return False

    def analyze(self) -> Dict[str, Any]:
        """
        Perform DNS analysis

        Returns:
            Dictionary containing DNS analysis results
        """
        self.logger.info("Analyzing DNS configuration...")

        # Analyze private DNS zone configuration
        self._analyze_private_dns_zone()

        # Analyze VNet DNS server configuration
        self._analyze_vnet_dns_servers()

        return self.dns_analysis

    def _analyze_private_dns_zone(self) -> None:
        """Analyze private DNS zone configuration for private clusters"""
        api_server_profile = self.cluster_info.get("api_server_access_profile")

        if not api_server_profile:
            self.dns_analysis = {
                "type": "none",
                "is_private_cluster": False,
                "vnet_integration": False,
                "private_dns_zone": None,
                "analysis": "No API server access profile found - not a private cluster",
            }
            return

        is_private = api_server_profile.get("enable_private_cluster", False)

        # Check for API Server VNet Integration
        vnet_integration = self._is_vnet_integration_enabled(api_server_profile)

        if not is_private:
            # Public cluster - check if it has VNet integration
            if vnet_integration:
                self.dns_analysis = {
                    "type": "vnet_integration_public",
                    "is_private_cluster": False,
                    "vnet_integration": True,
                    "private_dns_zone": None,
                    "analysis": "Public cluster with API Server VNet Integration - private DNS not required",
                }
                self.logger.warning("  API Server VNet Integration (public mode) - nodes use private IP without DNS")
            else:
                self.dns_analysis = {
                    "type": "none",
                    "is_private_cluster": False,
                    "vnet_integration": False,
                    "private_dns_zone": None,
                    "analysis": "Public cluster - private DNS not required",
                }
            return

        # Private cluster - analyze DNS configuration
        private_dns_zone = api_server_profile.get("private_dns_zone", "")

        if vnet_integration:
            # Private cluster with VNet integration - private DNS zone IS required (same as traditional private cluster)
            self.logger.warning("  API Server VNet Integration (private mode) - private DNS zone required")

        if private_dns_zone and private_dns_zone != "system":
            # Custom private DNS zone
            self.dns_analysis = {
                "type": "custom",
                "is_private_cluster": True,
                "vnet_integration": vnet_integration,
                "private_dns_zone": private_dns_zone,
                "analysis": "Custom private DNS zone configured",
            }

            self.logger.warning("  Custom private DNS zone: %s", private_dns_zone)

            # Note: VNet link validation is performed by misconfiguration_analyzer
            # which will create CRITICAL findings if VNet links are missing
        else:
            # System-managed private DNS zone
            self.dns_analysis = {
                "type": "system",
                "is_private_cluster": True,
                "vnet_integration": vnet_integration,
                "private_dns_zone": "system",
                "analysis": "System-managed private DNS zone",
            }

            self.logger.warning("  System-managed private DNS zone")

    def _is_vnet_integration_enabled(self, api_server_profile: Dict[str, Any]) -> bool:
        """
        Check if API Server VNet Integration is enabled.

        API Server VNet Integration projects the API server directly into a delegated subnet
        without requiring a private endpoint or tunnel. For public VNet integration clusters,
        no private DNS zone is needed since nodes connect directly via private IP.

        Args:
            api_server_profile: API server access profile dictionary

        Returns:
            True if VNet integration is enabled, False otherwise
        """
        # Check both top-level and additional_properties for backward compatibility
        if api_server_profile.get("enable_vnet_integration", False):
            return True
        additional_props = api_server_profile.get("additional_properties", {})
        return additional_props.get("enableVnetIntegration", False)

    def _analyze_vnet_dns_servers(self) -> None:
        """Analyze VNet DNS server configuration"""
        network_client = self.clients.get("network_client")
        if not network_client:
            self.logger.debug("  No network client available, skipping VNet DNS analysis")
            return

        try:
            # Get VNet subnet ID from cluster
            network_profile = self.cluster_info.get("network_profile", {})
            vnet_subnet_id = network_profile.get("vnet_subnet_id")

            if not vnet_subnet_id:
                # Try getting from first agent pool profile
                agent_pools = self.cluster_info.get("agent_pool_profiles", [])
                if agent_pools and len(agent_pools) > 0:
                    vnet_subnet_id = agent_pools[0].get("vnet_subnet_id")

            if not vnet_subnet_id:
                self.logger.debug("  No VNet subnet ID found in cluster info")
                return

            self.logger.debug("  Found VNet subnet ID: %s", vnet_subnet_id)

            # Parse VNet resource ID from subnet ID
            # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}  # pylint: disable=line-too-long
            parts = vnet_subnet_id.split("/")
            if len(parts) < 9:
                self.logger.warning("  Invalid subnet ID format: %s", vnet_subnet_id)
                return

            vnet_rg = parts[4]
            vnet_name = parts[8]

            # Get VNet details including DNS servers
            vnet = network_client.virtual_networks.get(vnet_rg, vnet_name)

            # Get DNS servers from VNet
            dhcp_options = vnet.dhcp_options
            dns_servers = dhcp_options.dns_servers if dhcp_options else []

            self.vnet_dns_servers = dns_servers or []
            self.dns_analysis["vnet_dns_servers"] = self.vnet_dns_servers

            if not dns_servers:
                # Using Azure default DNS
                self.logger.warning("  Using Azure default DNS (168.63.129.16)")
                self.dns_analysis["vnet_dns_config"] = "azure-default"
                return

            self.logger.warning("  Custom DNS servers configured: %s", ", ".join(dns_servers))
            self.dns_analysis["vnet_dns_config"] = "custom"

            # Check for potential issues with custom DNS
            is_private_cluster = self.dns_analysis.get("is_private_cluster", False)
            azure_dns = "168.63.129.16"
            has_azure_dns = azure_dns in dns_servers
            non_azure_dns = [dns for dns in dns_servers if dns != azure_dns]

            if non_azure_dns and is_private_cluster:
                # Private cluster with custom DNS - potential issue
                self.add_finding(
                    Finding.create_warning(
                        code=FindingCode.PRIVATE_DNS_MISCONFIGURED,
                        message=(
                            f"Private cluster is using custom DNS servers ({', '.join(non_azure_dns)}) "
                            f"which may not resolve Azure private DNS zones"
                        ),
                        recommendation=(
                            f"For private clusters, custom DNS servers must be configured to resolve Azure private DNS zones. "  # pylint: disable=line-too-long
                            f"Current DNS servers: {', '.join(dns_servers)}. "
                            f"Ensure one of the following: "
                            f"(1) DNS server VNet is linked to the private DNS zone, OR "
                            f"(2) Configure DNS forwarding to Azure DNS (168.63.129.16) for '*.privatelink.*.azmk8s.io', OR "  # pylint: disable=line-too-long
                            f"(3) Use Azure DNS (168.63.129.16) as primary DNS server."
                        ),
                        vnetName=vnet_name,
                        vnetResourceGroup=vnet_rg,
                        customDnsServers=non_azure_dns,
                        hasAzureDns=has_azure_dns,
                        privateDnsZone=self.dns_analysis.get("private_dns_zone"),
                    )
                )
                self.logger.warning("  Custom DNS servers may prevent private DNS resolution")

            elif non_azure_dns and not is_private_cluster:
                # Public cluster with custom DNS - medium risk
                self.add_finding(
                    Finding.create_warning(
                        code=FindingCode.DNS_RESOLUTION_FAILED,
                        message=(
                            f"VNet is using custom DNS servers ({', '.join(non_azure_dns)}) "
                            f"which may impact CoreDNS functionality"
                        ),
                        recommendation=(
                            f"Custom DNS servers should forward Azure service queries to Azure DNS (168.63.129.16). "  # pylint: disable=line-too-long
                            f"Current DNS servers: {', '.join(dns_servers)}. "
                            f"If experiencing DNS resolution issues, verify that:\n"
                            f"1. Custom DNS can reach Azure DNS (168.63.129.16)\n"
                            f"2. Azure-specific domains are forwarded correctly\n"
                            f"3. DNS forwarding is configured for '*.azmk8s.io' and other Azure services"
                        ),
                        vnetName=vnet_name,
                        vnetResourceGroup=vnet_rg,
                        customDnsServers=non_azure_dns,
                        hasAzureDns=has_azure_dns,
                    )
                )
                self.logger.warning("  Custom DNS may impact CoreDNS and Azure service resolution")

            elif has_azure_dns and len(dns_servers) > 1:
                # Mix of Azure DNS and custom DNS - informational
                self.logger.info("  VNet uses Azure DNS along with custom DNS servers")

        except (ResourceNotFoundError, HttpResponseError) as e:
            # Check if this is an authorization error
            if isinstance(e, HttpResponseError):
                if self._check_authorization_error(e, 'VNet', vnet_name, vnet_rg):
                    return  # Authorization error, finding already created
            self.logger.warning("  Unable to retrieve VNet information: %s", e)
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error("  Failed to analyze VNet DNS configuration: %s", e)

    def validate_private_dns_resolution(self, nslookup_output: str, hostname: str) -> bool:
        """
        Validate that DNS resolution returns a private IP address for private clusters

        Args:
            nslookup_output: Output from nslookup command
            hostname: The hostname that was resolved

        Returns:
            True if resolution is valid (returns private IP), False otherwise
        """
        try:
            # Convert compacted format back to regular format for parsing
            output_to_parse = nslookup_output.replace("\\n", "\n")

            # Check for DNS resolution failures first
            dns_error_patterns = [
                "nxdomain",
                "servfail",
                "refused",
                "can't find",
                "no servers could be reached",
                "communications error",
                "timed out",
            ]
            if any(error in output_to_parse.lower() for error in dns_error_patterns):
                self.logger.warning("DNS resolution failed for %s", hostname)
                return False

            # Parse nslookup output to extract IP addresses
            ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            found_ips = re.findall(ip_pattern, output_to_parse)

            if not found_ips:
                self.logger.warning("No IP addresses found in DNS response for %s", hostname)
                return False

            # Filter out DNS server IPs
            lines = output_to_parse.split("\n")
            dns_server_ips = set()
            in_server_section = False

            for line in lines:
                line_lower = line.lower()
                if "server:" in line_lower:
                    in_server_section = True
                    server_ips = re.findall(ip_pattern, line)
                    dns_server_ips.update(server_ips)
                elif in_server_section and "address:" in line_lower:
                    server_ips = re.findall(ip_pattern, line)
                    dns_server_ips.update(server_ips)
                    in_server_section = False
                elif "non-authoritative answer" in line_lower or "name:" in line_lower:
                    in_server_section = False

            # Check resolved IPs (excluding DNS server IPs)
            resolved_ips = [ip for ip in found_ips if ip not in dns_server_ips]

            if not resolved_ips:
                self.logger.warning("Only DNS server IPs found for %s, no actual resolution", hostname)
                return False

            # Check if any of the resolved IPs are private
            for ip_str in resolved_ips:
                try:
                    ip_addr = ipaddress.ip_address(ip_str)
                    if ip_addr.is_private:
                        self.logger.info("DNS resolved %s to private IP: %s", hostname, ip_str)
                        return True
                except ValueError:
                    continue

            # If we found IP addresses but none were private
            self.logger.warning("DNS resolved %s to public IP(s): %s", hostname, resolved_ips)

            # Create a finding for this issue
            self.add_finding(
                Finding.create_critical(
                    code=FindingCode.PRIVATE_DNS_MISCONFIGURED,
                    message=f"DNS resolution for {hostname} returned public IP instead of private IP",
                    recommendation="Verify that the VNet is linked to the private DNS zone and that DNS records are correctly configured",  # pylint: disable=line-too-long
                    hostname=hostname,
                    resolvedIPs=resolved_ips,
                    expectedBehavior="Private cluster API server should resolve to private IP address",
                    possibleCauses=[
                        "Private DNS zone link is missing",
                        "Private DNS zone link is in wrong VNet",
                        "Private DNS zone records are incorrect",
                    ],
                )
            )

            return False

        except Exception as e:  # pylint: disable=broad-except
            self.logger.error("Error validating DNS resolution for %s: %s", hostname, e)
            dns_error_patterns = [
                "nxdomain",
                "servfail",
                "refused",
                "can't find",
                "no servers could be reached",
                "communications error",
                "timed out",
            ]
            return not any(error in nslookup_output.lower() for error in dns_error_patterns)
