"""
Report Generator for AKS Network Diagnostics

This module handles generating and formatting diagnostic reports in multiple
formats:
- Console output (summary and detailed modes)
- JSON output for programmatic consumption
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class ReportGenerator:  # pylint: disable=too-many-instance-attributes
    """Generates diagnostic reports in various formats"""

    def __init__(
        self,
        cluster_name: str,
        resource_group: str,
        subscription: str,
        *,
        cluster_info: Dict[str, Any],
        agent_pools: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        vnets_analysis: List[Dict[str, Any]],
        route_table_analysis: Dict[str, Any],
        outbound_analysis: Dict[str, Any],
        outbound_ips: List[str],
        private_dns_analysis: Dict[str, Any],
        api_server_access_analysis: Dict[str, Any],
        vmss_analysis: List[Dict[str, Any]],
        vm_analysis: Optional[List[Dict[str, Any]]] = None,
        nsg_analysis: Dict[str, Any] = None,
        api_probe_results: Optional[Dict[str, Any]] = None,
        failure_analysis: Optional[Dict[str, Any]] = None,
        script_version: str = "2.2.0",
        subnet_cidrs: Optional[Dict[str, str]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize the ReportGenerator

        Args:
            cluster_name: AKS cluster name
            resource_group: Resource group name
            subscription: Azure subscription ID
            cluster_info: Cluster configuration dictionary
            agent_pools: List of agent pool configurations
            findings: List of diagnostic findings
            vnets_analysis: VNet analysis results
            route_table_analysis: Route table/UDR analysis results
            outbound_analysis: Outbound connectivity analysis
            outbound_ips: List of outbound public IPs
            private_dns_analysis: Private DNS analysis results
            api_server_access_analysis: API server access analysis
            vmss_analysis: VMSS configuration analysis
            vm_analysis: VM configuration analysis for Virtual Machines node pools
            nsg_analysis: NSG analysis results
            api_probe_results: API connectivity probe results
            failure_analysis: Failure analysis results
            script_version: Script version number
            subnet_cidrs: Optional dict mapping subnet IDs to CIDRs
            logger: Optional logger instance
        """
        self.cluster_name = cluster_name
        self.resource_group = resource_group
        self.subscription = subscription
        self.cluster_info = cluster_info
        self.agent_pools = agent_pools
        self.findings = findings
        self.vnets_analysis = vnets_analysis
        self.route_table_analysis = route_table_analysis
        self.outbound_analysis = outbound_analysis
        self.outbound_ips = outbound_ips
        self.private_dns_analysis = private_dns_analysis
        self.api_server_access_analysis = api_server_access_analysis
        self.vmss_analysis = vmss_analysis
        self.vm_analysis = vm_analysis or []
        self.nsg_analysis = nsg_analysis or {}
        self.api_probe_results = api_probe_results
        self.failure_analysis = failure_analysis or {"enabled": False}
        self.script_version = script_version
        self.subnet_cidrs = subnet_cidrs or {}
        self.logger = logger or logging.getLogger(__name__)
        self.show_details = False  # Set in print_console_report

    def generate_json_report(self) -> Dict[str, Any]:
        """
        Generate JSON report data

        Returns:
            Dictionary containing complete report data
        """
        return {
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": self.script_version,
                "generated_by": "AKS Network Diagnostics Script (Python)",
            },
            "cluster": {
                "name": self.cluster_name,
                "resource_group": self.resource_group,
                "subscription": self.subscription,
                "provisioning_state": self.cluster_info.get(
                    "provisioning_state",
                    ""
                ),
                "location": self.cluster_info.get("location", ""),
                "node_resource_group": self.cluster_info.get(
                    "node_resource_group",
                    ""
                ),
                "network_profile": self.cluster_info.get(
                    "network_profile",
                    {}
                ),
                "api_server_access": self.cluster_info.get(
                    "api_server_access_profile",
                    {}
                ),
            },
            "networking": {
                "vnets": self.vnets_analysis,
                "outbound": self.outbound_analysis,
                "private_dns": self.private_dns_analysis,
                "api_server_access": self.api_server_access_analysis,
                "vmss_configuration": self.vmss_analysis,
                "vm_configuration": self.vm_analysis,
                "nsg_configuration": self.nsg_analysis,
                "routing_analysis": {
                    "outbound_type": (
                        self.cluster_info.get("network_profile", {}).get(
                            "outbound_type",
                            "loadBalancer"
                        )
                    ),
                    "udr_analysis": (
                        self.outbound_analysis.get("udr_analysis")
                    ),
                },
            },
            "diagnostics": {
                "api_connectivity_probe": self.api_probe_results,
                "failure_analysis": self.failure_analysis,
                "findings": self.findings,
            },
        }

    def save_json_report(
        self,
        filepath: str,
        file_permissions: int = 0o600
    ) -> bool:
        """
        Save JSON report to file

        Args:
            filepath: Path to save the JSON report
            file_permissions: File permissions (default: owner read/write only)

        Returns:
            True if successful, False otherwise
        """
        try:
            report_data = self.generate_json_report()

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)

            # Set secure file permissions
            os.chmod(filepath, file_permissions)
            self.logger.info("[DOC] JSON report saved to: %s", filepath)
            return True

        except Exception as e:  # pylint: disable=broad-except
            self.logger.error("Failed to save JSON report: %s", e)
            return False

    def print_console_report(
        self,
        show_details: bool = False,
        json_report_path: Optional[str] = None
    ):
        """
        Print console report

        Args:
            show_details: Enable detailed output
            json_report_path: Path to JSON report if saved
        """
        # Store show_details as instance variable for use in helper methods
        self.show_details = show_details

        print("\n" + "=" * 74)

        if show_details:
            self._print_detailed_report()
        else:
            self._print_summary_report(json_report_path, show_details)

        print("\n[OK] AKS network assessment completed successfully!")

    def _print_summary_report(
        self,
        json_report_path: Optional[str] = None,
        show_details: bool = False
    ):
        """Print summary report"""
        print("# AKS Network Assessment Summary")
        print()
        print(
            f"**Cluster:** {self.cluster_name} "
            f"({self.cluster_info.get('provisioning_state', 'Unknown')})"
        )
        print(f"**Resource Group:** {self.resource_group}")
        print(
            f"**Generated:** "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        print()

        print("**Configuration:**")
        network_profile = self.cluster_info.get("network_profile", {})

        # Display network plugin with mode details
        self._print_network_plugin_info(network_profile)

        print(
            f"- Outbound Type: "
            f"{network_profile.get('outbound_type', 'loadBalancer')}"
        )

        api_server_profile = self.cluster_info.get("api_server_access_profile")
        is_private = (
            api_server_profile.get("enable_private_cluster", False)
            if api_server_profile else False
        )
        print(f"- Private Cluster: {str(is_private).lower()}")

        self._print_node_pools(show_details=show_details)
        self._print_outbound_configuration()
        self._print_connectivity_tests()

        print()
        print("**Findings Summary:**")

        # Separate permission findings from regular findings
        permission_findings = [
            f for f in self.findings
            if f.get("code", "").startswith("PERMISSION_INSUFFICIENT")
        ]
        critical_findings = [
            f for f in self.findings
            if f.get("severity") in ["critical", "error"] and
            not f.get("code", "").startswith("PERMISSION_INSUFFICIENT")
        ]
        warning_findings = [
            f for f in self.findings
            if f.get("severity") == "warning" and
            not f.get("code", "").startswith("PERMISSION_INSUFFICIENT")
        ]

        if len(critical_findings) == 0 and len(warning_findings) == 0:
            if permission_findings:
                # When there are permission limitations, provide context
                print("- [OK] No critical issues detected in analyzed components")
                print("- [WARNING] Analysis incomplete - see Permission Limitations below")
            else:
                # Normal case with full analysis
                print("- [OK] No critical issues detected")
        else:
            # Show critical/error findings
            for finding in critical_findings:
                # Map severity to correct label
                severity = finding.get("severity", "error")
                severity_label = "[CRITICAL]" if severity == "critical" else "[ERROR]"

                # For cluster operation failures, show only the error code
                # in summary mode
                if (finding.get("code") == "CLUSTER_OPERATION_FAILURE" and
                        finding.get("error_code")):
                    print(
                        f"- {severity_label} Cluster failed with error: "
                        f"{finding.get('error_code')}"
                    )
                else:
                    message = finding.get("message", "Unknown issue")
                    print(f"- {severity_label} {message}")

            # Show warning findings
            for finding in warning_findings:
                message = finding.get("message", "Unknown issue")
                print(f"- [WARNING] {message}")

            # If there are also permission limitations, add a note
            if permission_findings:
                print("- [WARNING] Analysis incomplete - see Permission Limitations below")

        # Show permission findings in a separate section
        if permission_findings:
            print()
            print("**Permission Limitations:**")
            print("The following checks were incomplete due to missing permissions:")
            for finding in permission_findings:
                message = finding.get("message", "Unknown issue")
                recommendation = finding.get("recommendation", "")
                print(f"- {message}")
                if recommendation and show_details:
                    # Only show recommendation in details mode
                    print(f"  → {recommendation}")

        print()
        if json_report_path:
            print(f"[DOC] JSON report saved to: {json_report_path}")
        print("Tip: Use --details flag for detailed analysis")

    def _get_cni_mode_description(self, network_profile: Dict[str, Any]) -> str:
        """
        Get user-friendly CNI mode description.

        This method determines the CNI mode based on network profile settings
        and returns a human-readable description.

        Args:
            network_profile: Network profile dictionary from cluster info

        Returns:
            String describing the CNI mode (e.g., "Azure CNI Overlay", "Kubenet")
        """
        network_plugin = network_profile.get("network_plugin", "kubenet")
        network_plugin_mode = network_profile.get("network_plugin_mode")
        network_dataplane = network_profile.get("network_dataplane", "azure")

        # Build the CNI mode description
        cni_description = network_plugin

        if network_plugin == "azure":
            if network_plugin_mode == "overlay":
                cni_description = "Azure CNI Overlay"
            elif network_dataplane == "cilium":
                # Azure CNI with Cilium dataplane
                if network_plugin_mode == "overlay":
                    cni_description = "Azure CNI Overlay + Cilium"
                else:
                    cni_description = "Azure CNI + Cilium"
            elif any(pool.get("pod_subnet_id") for pool in self.agent_pools):
                # Azure CNI with pod subnets
                cni_description = "Azure CNI (Pod Subnet)"
            else:
                # Legacy Azure CNI (node subnet only)
                cni_description = "Azure CNI (Node Subnet)"
        elif network_plugin == "kubenet":
            cni_description = "Kubenet"
        elif network_plugin == "none":
            cni_description = "BYO CNI (Bring Your Own CNI)"

        return cni_description

    def _print_network_plugin_info(self, network_profile: Dict[str, Any]):
        """
        Print detailed network plugin configuration information.

        This displays the CNI mode, dataplane, and policy to help users understand
        their AKS networking setup.

        Args:
            network_profile: Network profile dictionary from cluster info
        """
        network_policy = network_profile.get("network_policy", "none")
        network_dataplane = network_profile.get("network_dataplane", "azure")
        pod_cidr = network_profile.get("pod_cidr")

        # Get CNI mode description using shared helper
        cni_description = self._get_cni_mode_description(network_profile)

        print(f"- Network Plugin: {cni_description}")

        # Show pod CIDR if available (for overlay and kubenet)
        if pod_cidr:
            print(f"  - Pod CIDR: {pod_cidr}")

        # Show network policy if configured
        if network_policy and network_policy != "none":
            print(f"  - Network Policy: {network_policy}")

        # Show dataplane if not default Azure
        if network_dataplane and network_dataplane != "azure":
            print(f"  - Network Dataplane: {network_dataplane}")

    def _get_pool_count_and_size(self, pool: Dict[str, Any]) -> tuple:
        """
        Get node count and VM size for a pool.

        Args:
            pool: Agent pool dictionary

        Returns:
            Tuple of (count, vm_size)
        """
        pool_type = pool.get("type", "VirtualMachineScaleSets")

        if pool_type == "VirtualMachines":
            # For VM pools, use virtualMachinesProfile or virtualMachineNodesStatus
            vm_profile = pool.get("virtual_machines_profile", {})
            scale_profile = vm_profile.get("scale", {})
            manual_sizes = scale_profile.get("manual", [])

            # Also check virtualMachineNodesStatus for actual status
            vm_status = pool.get("virtual_machine_nodes_status", [])
            if vm_status:
                manual_sizes = vm_status

            if manual_sizes:
                # Count total nodes across all VM sizes
                count = sum(size.get("count", 0) for size in manual_sizes)
                # Get first VM size for display
                vm_size = manual_sizes[0].get("size", "unknown") if manual_sizes else "unknown"
            else:
                # Fallback to standard count field
                count = pool.get("count") or 0
                vm_size = pool.get("vm_size", "unknown")
        else:
            # VMSS pools use standard count and vm_size
            count = pool.get("count", 0)
            vm_size = pool.get("vm_size", "unknown")

        return count, vm_size

    def _get_subnet_display(self, subnet_id: str) -> str:
        """
        Get subnet display string with CIDR if available.

        Args:
            subnet_id: Subnet resource ID

        Returns:
            Subnet display string (name or name with CIDR)
        """
        if not subnet_id:
            return "N/A"

        subnet_name = subnet_id.split("/")[-1] if "/" in subnet_id else subnet_id

        # Look up CIDR if available
        if self.subnet_cidrs:
            cidr = self.subnet_cidrs.get(subnet_id.lower())
            if cidr:
                return f"{subnet_name} ({cidr})"

        return subnet_name

    def _print_vm_pool_sizes(self, pool: Dict[str, Any], count: int, vm_size: str):
        """
        Print VM sizes for Virtual Machines pool type (compact format).

        Args:
            pool: Agent pool dictionary
            count: Total node count
            vm_size: Default VM size
        """
        vm_profile = pool.get("virtual_machines_profile", {})
        scale_profile = vm_profile.get("scale", {})
        manual_sizes = scale_profile.get("manual", [])

        # Also check virtualMachineNodesStatus
        vm_status = pool.get("virtual_machine_nodes_status", [])
        if vm_status:
            manual_sizes = vm_status

        if manual_sizes and len(manual_sizes) > 0:
            if len(manual_sizes) == 1:
                # Single VM size
                size_info = manual_sizes[0]
                vm_size = size_info.get('size', 'unknown')
                vm_count = size_info.get('count', 0)
                print(f"  - VM Size: {vm_size}, Count: {vm_count}")
            else:
                # Multiple VM sizes
                print("  - VM Sizes:")
                for size_info in manual_sizes:
                    size_name = size_info.get('size', 'unknown')
                    size_count = size_info.get('count', 0)
                    print(f"    - {size_name}: {size_count} nodes")
                print(f"  - Total Nodes: {count}")
        else:
            # Fallback
            print(f"  - VM Size: {vm_size}, Count: {count}")

    def _print_vm_pool_sizes_detailed(self, pool: Dict[str, Any], count: int, vm_size: str):
        """
        Print VM sizes for Virtual Machines pool type (detailed format).

        Args:
            pool: Agent pool dictionary
            count: Total node count
            vm_size: Default VM size
        """
        vm_profile = pool.get("virtual_machines_profile", {})
        scale_profile = vm_profile.get("scale", {})
        manual_sizes = scale_profile.get("manual", [])

        # Also check virtualMachineNodesStatus
        vm_status = pool.get("virtual_machine_nodes_status", [])
        if vm_status:
            manual_sizes = vm_status

        if manual_sizes and len(manual_sizes) > 0:
            if len(manual_sizes) == 1:
                # Single VM size - simple display
                size_info = manual_sizes[0]
                print(f"- VM Size: {size_info.get('size', 'unknown')}")
                print(f"- Count: {size_info.get('count', 0)}")
            else:
                # Multiple VM sizes - show detailed breakdown
                print("- VM Sizes:")
                for size_info in manual_sizes:
                    size_name = size_info.get("size", "unknown")
                    node_count = size_info.get("count", 0)
                    print(f"  - {size_name}: {node_count} nodes")
                print(f"- Total Nodes: {count}")
        else:
            # Fallback to standard display
            print(f"- VM Size: {vm_size}")
            print(f"- Count: {count}")

    def _print_node_pools(self, show_details: bool = False):
        """Print node pool information section

        Args:
            show_details: If True, show full details. If False, show compact summary.
        """
        if not self.agent_pools or len(self.agent_pools) == 0:
            return

        # Always show node pools for better visibility
        print()
        print("**Node Pools:**")

        for pool in self.agent_pools:
            name = pool.get("name", "unknown")
            mode = pool.get("mode", "User")
            pool_type = pool.get("type", "VirtualMachineScaleSets")

            # Get count and VM size using helper method
            count, vm_size = self._get_pool_count_and_size(pool)

            # Get subnet info with CIDR using helper method
            vnet_subnet_id = pool.get("vnet_subnet_id")
            subnet_display = self._get_subnet_display(vnet_subnet_id)

            if show_details:
                # Detailed view: show all information with indentation
                os_type = pool.get("os_type", "Linux")

                # Format pool header based on type
                if pool_type == "VirtualMachines":
                    print(f"- {name} ({mode}, {os_type}, Virtual Machines)")
                else:
                    print(f"- {name} ({mode}, {os_type})")

                # Show VM sizes using helper method
                if pool_type == "VirtualMachines":
                    self._print_vm_pool_sizes(pool, count, vm_size)
                else:
                    print(f"  - VM Size: {vm_size}, Count: {count}")

                print(f"  - Node Subnet: {subnet_display}")

                # Show pod subnet for Azure CNI Pod Subnet mode
                pod_subnet_id = pool.get("pod_subnet_id")
                if pod_subnet_id:
                    pod_subnet_display = self._get_subnet_display(pod_subnet_id)
                    print(f"  - Pod Subnet: {pod_subnet_display}")
            else:
                # Compact summary view: single line per pool
                type_suffix = " [VM]" if pool_type == "VirtualMachines" else ""
                print(f"- {name} ({mode}, Count: {count}, Subnet: {subnet_display}){type_suffix}")

    def _print_outbound_configuration(self):
        """Print outbound IP configuration section"""
        effective_outbound = self.cluster_info.get("effective_outbound_type")

        # Check if we have permission issues
        has_lb_permission_issue = any(
            f.get("code") == "PERMISSION_INSUFFICIENT_LB"
            for f in self.findings
        )
        has_vnet_permission_issue = any(
            f.get("code") == "PERMISSION_INSUFFICIENT_VNET"
            for f in self.findings
        )

        # Get configured outbound type
        configured_type = self.cluster_info.get(
            "network_profile", {}
        ).get("outbound_type", "loadBalancer")

        # Always show outbound configuration section if it's a loadBalancer type
        # or if we have IPs or effective override
        show_section = (
            self.outbound_ips or
            effective_outbound or
            configured_type == "loadBalancer" or
            has_lb_permission_issue or
            has_vnet_permission_issue
        )

        if show_section:
            print()
            print("**Outbound Configuration:**")

            # Check if we have UDR override situation
            if effective_outbound and effective_outbound != configured_type:
                # UDR override detected
                print(
                    f"- Configured Type: {configured_type} "
                    f"(overridden by UDR to {effective_outbound})"
                )
                if effective_outbound == "userDefinedRouting":
                    print(
                        "- Effective IPs: Determined by User Defined Routes "
                        "(route table)"
                    )
            elif configured_type == "loadBalancer":
                if has_lb_permission_issue or has_vnet_permission_issue:
                    # Permission issue prevents reading LoadBalancer details
                    print("- Load Balancer IPs: Unable to retrieve (insufficient permissions)")
                elif self.outbound_ips:
                    # Regular load balancer with IPs
                    ip_list = ", ".join(self.outbound_ips)
                    print(f"- Load Balancer IPs: {ip_list}")
                else:
                    # No IPs and no permission issue - might be misconfiguration
                    print("- Load Balancer IPs: None detected")
            elif configured_type == "userDefinedRouting":
                # Regular UDR
                print(
                    "- Effective IPs: Determined by User Defined Routes "
                    "(route table)"
                )
            elif configured_type == "managedNATGateway":
                print("- Outbound: Managed NAT Gateway")
                if self.outbound_ips:
                    ip_list = ", ".join(self.outbound_ips)
                    print(f"- NAT Gateway IPs: {ip_list}")
            elif configured_type == "userAssignedNATGateway":
                print("- Outbound: User-Assigned NAT Gateway")
                if self.outbound_ips:
                    ip_list = ", ".join(self.outbound_ips)
                    print(f"- NAT Gateway IPs: {ip_list}")
                else:
                    print("- NAT Gateway IPs: None detected")

    def _print_connectivity_tests(self):
        """Print connectivity test results section"""
        api_probe_results = self.cluster_info.get("api_probe_results")

        if api_probe_results and api_probe_results.get("enabled"):
            print()
            print("**Connectivity Tests:**")

            summary = api_probe_results.get("summary", {})
            total_tests = summary.get("total_tests", 0)
            passed = summary.get("passed", 0)
            failed = summary.get("failed", 0)
            errors = summary.get("errors", 0)

            # Show summary
            if total_tests > 0:
                print(
                    f"- Total: {total_tests} tests "
                    f"({passed} passed, {failed} failed, {errors} errors)"
                )

                # Build breakdown only showing non-zero values
                breakdown_parts = []
                if passed > 0:
                    breakdown_parts.append(f"{passed} passed")
                if failed > 0:
                    breakdown_parts.append(f"{failed} failed")
                if errors > 0:
                    breakdown_parts.append(f"{errors} errors")

                if breakdown_parts:
                    breakdown = ", ".join(breakdown_parts)
                    print(f"  Breakdown: {breakdown}")
            else:
                print("- No tests executed")

    def _print_detailed_report(self):
        """Print detailed report"""
        print("# AKS Network Assessment Report")
        print()
        print(f"**Cluster:** {self.cluster_name}")
        print(f"**Resource Group:** {self.resource_group}")
        print(f"**Subscription:** {self.subscription}")
        print(
            f"**Generated:** "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        print()

        # Cluster overview
        self._print_cluster_overview()

        # Network configuration
        self._print_network_configuration()

        # Connectivity test results
        self._print_connectivity_tests()

        # NSG Analysis
        self._print_nsg_analysis()

        # Findings
        self._print_findings()

    def _print_cluster_overview(self):
        """Print cluster overview section"""
        print("## Cluster Overview")
        print()
        print("| Property | Value |")
        print("|----------|-------|")
        print(
            f"| Provisioning State | "
            f"{self.cluster_info.get('provisioning_state', '')} |"
        )

        # Show power state
        power_state = self.cluster_info.get("power_state", {})
        power_code = (
            power_state.get("code", "Unknown")
            if isinstance(power_state, dict)
            else str(power_state)
        )
        print(f"| Power State | {power_code} |")

        print(f"| Location | {self.cluster_info.get('location', '')} |")

        # Get network plugin description using shared helper
        network_profile = self.cluster_info.get("network_profile", {})
        cni_description = self._get_cni_mode_description(network_profile)

        print(f"| Network Plugin | {cni_description} |")
        print(
            f"| Outbound Type | "
            f"{network_profile.get('outbound_type', 'loadBalancer')} |"
        )

        api_server_profile = self.cluster_info.get("api_server_access_profile")
        is_private = (
            api_server_profile.get("enable_private_cluster", False)
            if api_server_profile else False
        )
        print(f"| Private Cluster | {str(is_private).lower()} |")
        print()

    def _print_network_configuration(self):
        """Print network configuration section"""
        print("## Network Configuration")
        print()

        # Service Network
        network_profile = self.cluster_info.get("network_profile", {})
        print("### Service Network")
        print(f"- **Service CIDR:** {network_profile.get('service_cidr', '')}")
        print(
            f"- **DNS Service IP:** "
            f"{network_profile.get('dns_service_ip', '')}"
        )

        # Handle Pod CIDR display based on CNI mode
        pod_cidr = network_profile.get('pod_cidr', '')
        has_pod_subnets = any(pool.get("pod_subnet_id") for pool in self.agent_pools)

        if has_pod_subnets:
            # Pod subnet mode - no cluster-wide pod CIDR
            print("- **Pod CIDR:** N/A (using pod subnets)")
        elif pod_cidr:
            # Overlay or Kubenet with pod CIDR
            print(f"- **Pod CIDR:** {pod_cidr}")
        else:
            # Legacy Azure CNI or other modes
            print("- **Pod CIDR:** N/A (node subnet mode)")

        # Show network policy if configured
        network_policy = network_profile.get('network_policy', 'none')
        if network_policy and network_policy != 'none':
            print(f"- **Network Policy:** {network_policy}")

        # Show network dataplane if not default
        network_dataplane = network_profile.get('network_dataplane', 'azure')
        if network_dataplane and network_dataplane != 'azure':
            print(f"- **Network Dataplane:** {network_dataplane}")

        print()

        # Node Pools - always show in detailed mode for visibility
        if self.agent_pools:
            print("### Node Pools")
            print()
            for pool in self.agent_pools:
                name = pool.get("name", "unknown")
                mode = pool.get("mode", "User")
                pool_type = pool.get("type", "VirtualMachineScaleSets")
                os_type = pool.get("os_type", "Linux")

                # Format header based on pool type
                if pool_type == "VirtualMachines":
                    print(f"**{name}** ({mode}, {os_type}, Virtual Machines)")
                else:
                    print(f"**{name}** ({mode}, {os_type})")

                # Get count and VM size using helper method
                count, vm_size = self._get_pool_count_and_size(pool)

                # Show VM sizes and count based on pool type
                if pool_type == "VirtualMachines":
                    # Use helper method for VM pool sizes display
                    self._print_vm_pool_sizes_detailed(pool, count, vm_size)
                else:
                    # VMSS pools use standard display
                    print(f"- VM Size: {vm_size}")
                    print(f"- Count: {count}")

                # Show node subnet with CIDR using helper method
                vnet_subnet_id = pool.get("vnet_subnet_id")
                if vnet_subnet_id:
                    subnet_display = self._get_subnet_display(vnet_subnet_id)
                    print(f"- Node Subnet: {subnet_display}")

                # Show pod subnet with CIDR using helper method
                pod_subnet_id = pool.get("pod_subnet_id")
                if pod_subnet_id:
                    subnet_display = self._get_subnet_display(pod_subnet_id)
                    print(f"- Pod Subnet: {subnet_display}")

                print()

        # API Server access
        self._print_api_server_access()

        # Outbound connectivity
        self._print_outbound_connectivity()

        # UDR Analysis
        self._print_udr_analysis()

    # pylint: disable=too-many-branches
    def _print_api_server_access(self):
        """Print API server access section"""
        print("### API Server Access")
        api_server_profile = self.cluster_info.get("api_server_access_profile")
        is_private = (
            api_server_profile.get("enable_private_cluster", False)
            if api_server_profile else False
        )

        # Check for VNet integration
        vnet_integration = False
        if api_server_profile:
            # Check both top-level and additional_properties for backward compatibility
            vnet_integration = api_server_profile.get("enable_vnet_integration", False)
            if not vnet_integration:
                additional_props = api_server_profile.get("additional_properties", {})
                vnet_integration = additional_props.get("enableVnetIntegration", False)

        # Determine access mode
        if vnet_integration:
            if is_private:
                print("- **Type:** Private cluster with API Server VNet Integration")
                print("- **Access Mode:** API server projected into delegated subnet (private mode)")
            else:
                print("- **Type:** Public cluster with API Server VNet Integration")
                print("- **Access Mode:** API server projected into delegated subnet (public access enabled)")
        elif is_private:
            print("- **Type:** Private cluster (Private Endpoint)")
            print("- **Access Mode:** Private endpoint via Private Link")
        else:
            print("- **Type:** Public cluster")

        if is_private and api_server_profile:
            # Try multiple sources for private FQDN
            private_fqdn = ""
            if api_server_profile.get("private_fqdn"):
                private_fqdn = api_server_profile.get("private_fqdn", "")
            elif self.cluster_info.get("private_fqdn"):
                private_fqdn = self.cluster_info.get("private_fqdn", "")

            print(f"- **Private FQDN:** {private_fqdn}")

            # Check if public FQDN is also enabled (default for private clusters)
            public_fqdn_enabled = api_server_profile.get("enable_private_cluster_public_fqdn")
            if public_fqdn_enabled is None:
                # Check alternative property name
                public_fqdn_enabled = api_server_profile.get("enablePrivateClusterPublicFqdn", True)

            if public_fqdn_enabled:
                public_fqdn = self.cluster_info.get('fqdn', '')
                print(f"- **Public FQDN:** {public_fqdn} (enabled for private cluster)")
            else:
                print("- **Public FQDN:** Disabled (private-only access)")

            print(
                f"- **Private DNS Zone:** "
                f"{api_server_profile.get('private_dns_zone', '')}"
            )
        else:
            print(f"- **Public FQDN:** {self.cluster_info.get('fqdn', '')}")

        # Add authorized IP ranges information
        if api_server_profile:
            authorized_ranges = api_server_profile.get(
                "authorized_ip_ranges",
                []
            )
            if authorized_ranges:
                print(
                    f"- **Authorized IP Ranges:** "
                    f"{len(authorized_ranges)} range(s)"
                )
                for range_cidr in authorized_ranges:
                    print(f"  - {range_cidr}")

                # Show access implications if we have the analysis
                if self.api_server_access_analysis:
                    access_restrictions = (
                        self.api_server_access_analysis.get(
                            "access_restrictions",
                            {}
                        )
                    )
                    implications = access_restrictions.get(
                        "implications",
                        []
                    )
                    if implications:
                        print("- **Access Implications:**")
                        for implication in implications:
                            print(f"  {implication}")
            else:
                # No authorized IP ranges configured
                if is_private:
                    # Private cluster - access is restricted by design
                    if vnet_integration:
                        print(
                            "- **Access Restrictions:** Private cluster "
                            "(access via VNet integration)"
                        )
                    else:
                        print(
                            "- **Access Restrictions:** Private cluster "
                            "(access via private endpoint)"
                        )
                else:
                    # Public cluster with no IP restrictions
                    print(
                        "- **Access Restrictions:** None "
                        "(unrestricted public access)"
                    )
                    print(
                        "  [WARNING] API server is accessible from any IP "
                        "address on the internet"
                    )

        print()

    def _print_outbound_connectivity(self):
        """Print outbound connectivity section"""
        if self.outbound_ips:
            network_profile = self.cluster_info.get("network_profile", {})
            print("### Outbound Connectivity")
            print(
                f"- **Type:** "
                f"{network_profile.get('outbound_type', 'loadBalancer')}"
            )
            print("- **Effective Public IPs:**")
            for ip in self.outbound_ips:
                print(f"  - {ip}")
            print()

    def _print_udr_analysis(self):
        """Print UDR analysis section"""
        udr_analysis = (
            self.outbound_analysis.get("udr_analysis")
            if self.outbound_analysis else None
        )
        if udr_analysis:
            print("### User Defined Routes Analysis")
            route_tables = udr_analysis.get("route_tables", [])
            if route_tables:
                print(f"- **Route Tables Found:** {len(route_tables)}")

                for rt in route_tables:
                    print(f"- **Route Table:** {rt.get('name', 'unnamed')}")
                    print(
                        f"  - **Resource Group:** "
                        f"{rt.get('resource_group', '')}"
                    )
                    print(
                        f"  - **BGP Propagation:** "
                        f"{'Disabled' if rt.get('disable_bgp_route_propagation') else 'Enabled'}"
                    )
                    print(f"  - **Routes:** {len(rt.get('routes', []))}")

                    # Show critical routes
                    critical_routes = [
                        r for r in rt.get("routes", [])
                        if r.get("impact", {}).get("severity") in [
                            "critical",
                            "high"
                        ]
                    ]
                    if critical_routes:
                        print("  - **Critical Routes:**")
                        for route in critical_routes:
                            impact = route.get("impact", {})
                            print(
                                f"    - {route.get('name', 'unnamed')} "
                                f"({route.get('address_prefix', '')}) -> "
                                f"{route.get('next_hop_type', '')} - "
                                f"{impact.get('description', '')}"
                            )

                # Show virtual appliance routes summary
                va_routes = udr_analysis.get("virtual_appliance_routes", [])
                if va_routes:
                    print(
                        f"- **Virtual Appliance Routes:** "
                        f"{len(va_routes)}"
                    )
                    for route in va_routes:
                        print(
                            f"  - {route.get('name', 'unnamed')} "
                            f"({route.get('address_prefix', '')}) -> "
                            f"{route.get('next_hop_ip_address', '')}"
                        )

                print()
            else:
                if udr_analysis.get("incomplete_due_to_permissions"):
                    print(
                        "- **No route tables found** "
                        "(analysis incomplete due to insufficient permissions)"
                    )
                else:
                    print("- **No route tables found on node subnets**")
                print()

    def _print_connectivity_tests(self):
        """Print connectivity test results section"""
        if self.api_probe_results:
            print()
            print("### Connectivity Tests")

            if self.api_probe_results.get("skipped"):
                reason = self.api_probe_results.get("reason", "Unknown reason")
                print(f"- **Status:** Skipped ({reason})")
                print()
            else:
                summary = self.api_probe_results.get("summary", {})
                total = summary.get("total_tests", 0)
                passed = summary.get("passed", 0)
                failed = summary.get("failed", 0)
                errors = summary.get("errors", 0)

                print(f"- **Total Tests:** {total}")
                if passed > 0:
                    print(f"- **[OK] Passed:** {passed}")
                if failed > 0:
                    print(f"- **[ERROR] Failed:** {failed}")
                if errors > 0:
                    print(f"- **[WARNING] Execution Failed:** {errors}")

                # Show detailed results only when --details flag is used
                if self.show_details:
                    tests = self.api_probe_results.get("tests", [])
                    if tests:
                        print("\n**Test Details:**")
                        for test in tests:
                            self._print_test_detail(test)
                print()

    def _print_test_detail(self, test: Dict[str, Any]):
        """Print individual test detail"""
        status_icon = {
            "passed": "[OK]",
            "failed": "[ERROR]",
            "error": "[WARNING]",
            "skipped": "[SKIP]",
        }.get(test.get("status"), "[?]")

        test_name = test.get("test_name", "Unknown Test")
        vmss_name = test.get("vmss_name", "unknown")
        exit_code = test.get("exit_code", -1)
        print(
            f"- {status_icon} **{test_name}** "
            f"(VMSS: {vmss_name}, Exit Code: {exit_code})"
        )

        # Show full test result in JSON format with compacted newlines
        test_copy = test.copy()
        # Compact stdout and stderr for single-line display
        if test_copy.get("stdout"):
            test_copy["stdout"] = test_copy["stdout"].replace("\n", "\\n")
        if test_copy.get("stderr"):
            test_copy["stderr"] = test_copy["stderr"].replace("\n", "\\n")

        print("  - **Full Test Result:**")
        print("    ```json")
        print(f"    {json.dumps(test_copy, indent=2)}")
        print("    ```")

    def _print_nsg_analysis(self):
        """Print NSG analysis section"""
        if self.nsg_analysis:
            print("### Network Security Group (NSG) Analysis")

            # Check if analysis is incomplete due to permissions
            if self.nsg_analysis.get("incomplete_due_to_permissions"):
                print(
                    "- **Analysis incomplete** due to insufficient permissions "
                    "to read VMSS/VNet configuration"
                )
                print("- **NSGs Analyzed:** 0")
                print()
                return

            # NSG Analysis Summary
            subnet_nsgs = self.nsg_analysis.get("subnet_nsgs", [])
            nic_nsgs = self.nsg_analysis.get("nic_nsgs", [])
            total_nsgs = len(subnet_nsgs) + len(nic_nsgs)
            blocking_rules = self.nsg_analysis.get("blocking_rules", [])
            inter_node_communication = self.nsg_analysis.get(
                "inter_node_communication",
                {}
            )
            inter_node_status = inter_node_communication.get(
                "status",
                "unknown"
            )

            print(f"- **NSGs Analyzed:** {total_nsgs}")
            print(f"- **Issues Found:** {len(blocking_rules)}")

            # Inter-node communication status
            status_icon = {
                "ok": "[OK]",
                "potential_issues": "[WARNING]",
                "blocked": "[ERROR]",
                "unknown": "[?]"
            }.get(inter_node_status, "[?]")
            status_messages = {
                "ok": "Not blocked",
                "potential_issues": "Potential issues",
                "blocked": "Blocked",
                "unknown": "Unknown",
            }
            status_text = status_messages.get(
                inter_node_status,
                inter_node_status.replace("_", " ").title()
            )
            print(
                f"- **Inter-node Communication:** "
                f"{status_icon} {status_text}"
            )

            # Show detailed NSG information
            if total_nsgs > 0:
                print()
                self._print_subnet_nsgs(subnet_nsgs)
                self._print_nic_nsgs(nic_nsgs)
                self._print_blocking_rules(blocking_rules)

            print()

    def _print_subnet_nsgs(self, subnet_nsgs: List[Dict[str, Any]]):
        """Print subnet NSGs section"""
        if subnet_nsgs:
            print("**Subnet NSGs:**")
            for nsg in subnet_nsgs:
                nsg_name = nsg.get("nsg_name", "unknown")
                subnet_name = nsg.get("subnet_name", "unknown")
                custom_rules = len(nsg.get("rules", []))
                default_rules = len(nsg.get("default_rules", []))

                print(f"- **{subnet_name}** -> NSG: {nsg_name}")
                print(
                    f"  - Custom Rules: {custom_rules}, "
                    f"Default Rules: {default_rules}"
                )

                # Show custom rules
                if custom_rules > 0 and nsg.get("rules"):
                    print("  - **Custom Rules:**")
                    for rule in nsg.get("rules", []):
                        self._print_nsg_rule(rule)

    def _print_nic_nsgs(self, nic_nsgs: List[Dict[str, Any]]):
        """Print NIC NSGs section"""
        if nic_nsgs:
            print("\n**NIC NSGs:**")

            # Group NICs by NSG name to avoid duplicates
            nsg_groups = {}
            for nsg in nic_nsgs:
                nsg_name = nsg.get("nsg_name", "unknown")
                vmss_name = nsg.get("vmss_name", "unknown")

                if nsg_name not in nsg_groups:
                    nsg_groups[nsg_name] = {
                        "nsg_data": nsg,
                        "vmss_list": []
                    }
                nsg_groups[nsg_name]["vmss_list"].append(vmss_name)

            # Display each unique NSG with its associated VMSS instances
            for nsg_name, group_data in nsg_groups.items():
                nsg = group_data["nsg_data"]
                vmss_list = group_data["vmss_list"]
                custom_rules = len(nsg.get("rules", []))
                default_rules = len(nsg.get("default_rules", []))

                # Show NSG with all VMSS instances using it
                vmss_names = ", ".join(vmss_list)
                print(f"- **{nsg_name}** (used by: {vmss_names})")
                print(
                    f"  - Custom Rules: {custom_rules}, "
                    f"Default Rules: {default_rules}"
                )

                # Show custom rules if any
                if custom_rules > 0 and nsg.get("rules"):
                    print("  - **Custom Rules:**")
                    for rule in nsg.get("rules", []):
                        self._print_nsg_rule(rule)

    def _print_nsg_rule(self, rule: Dict[str, Any]):
        """Print NSG rule details"""
        access = rule.get("access", "Unknown")
        direction = rule.get("direction", "Unknown")
        priority = rule.get("priority", "Unknown")
        protocol = rule.get("protocol", "Unknown")
        dest = rule.get("destination_address_prefix", "Unknown")
        ports = rule.get("destination_port_range", "Unknown")

        access_icon = "[OK]" if access.lower() == "allow" else "[X]"
        print(
            f"    - {access_icon} **{rule.get('name', 'Unknown')}** "
            f"(Priority: {priority})"
        )
        print(f"      - {direction} {protocol} to {dest} on ports {ports}")

    def _print_blocking_rules(self, blocking_rules: List[Dict[str, Any]]):
        """Print blocking rules section"""
        if blocking_rules:
            print("\n**[WARNING] Potentially Blocking Rules:**")
            for rule in blocking_rules:
                print(
                    f"- **{rule.get('rule_name', 'Unknown')}** "
                    f"in NSG {rule.get('nsg_name', 'Unknown')}"
                )
                print(f"  - Priority: {rule.get('priority', 'Unknown')}")
                print(f"  - Direction: {rule.get('direction', 'Unknown')}")
                print(f"  - Protocol: {rule.get('protocol', 'Unknown')}")
                print(f"  - Destination: {rule.get('destination', 'Unknown')}")
                print(f"  - Ports: {rule.get('ports', 'Unknown')}")
                print(f"  - Impact: {rule.get('impact', 'Unknown')}")

    def _print_findings(self):
        """Print findings section"""
        if self.findings:
            print("## Findings")
            print()

            # Separate permission findings from regular findings
            permission_findings = [
                f for f in self.findings
                if f.get("code", "").startswith("PERMISSION_INSUFFICIENT")
            ]
            regular_findings = [
                f for f in self.findings
                if not f.get("code", "").startswith("PERMISSION_INSUFFICIENT")
            ]

            # Count regular findings by severity
            critical_count = len([
                f for f in regular_findings
                if f.get("severity") == "critical"
            ])
            error_count = len([
                f for f in regular_findings
                if f.get("severity") == "error"
            ])
            warning_count = len([
                f for f in regular_findings
                if f.get("severity") == "warning"
            ])
            info_count = len([
                f for f in regular_findings
                if f.get("severity") == "info"
            ])

            # Display findings summary
            print("**Findings Summary:**")
            if critical_count > 0:
                print(f"- [CRITICAL] {critical_count}")
            if error_count > 0:
                print(f"- [ERROR] {error_count}")
            if warning_count > 0:
                print(f"- [WARNING] {warning_count}")
            if info_count > 0:
                print(f"- [INFO] {info_count}")
            print()

            # Define severity order (most severe first)
            severity_order = {
                "critical": 0,
                "high": 1,
                "error": 1,
                "warning": 2,
                "info": 3
            }

            # Sort regular findings by severity
            sorted_findings = sorted(
                regular_findings,
                key=lambda f: severity_order.get(f.get("severity", "info"), 3)
            )

            # Display all regular findings in detail
            for finding in sorted_findings:
                severity_icon = {
                    "critical": "[CRITICAL]",
                    "error": "[ERROR]",
                    "warning": "[WARNING]",
                    "info": "[INFO]",
                }.get(finding.get("severity", "info"), "[INFO]")

                print(
                    f"### {severity_icon} "
                    f"{finding.get('code', 'UNKNOWN')}"
                )
                print(f"**Message:** {finding.get('message', '')}")
                if finding.get("recommendation"):
                    print(
                        f"**Recommendation:** "
                        f"{finding.get('recommendation', '')}"
                    )
                print()

            # Display permission findings in a separate section
            if permission_findings:
                print("## Permission Limitations")
                print()
                print(
                    "**Note:** The following checks were incomplete due to "
                    "missing permissions. Results may not reflect the "
                    "complete network configuration."
                )
                print()

                for finding in permission_findings:
                    print(f"### [WARNING] {finding.get('code', 'UNKNOWN')}")
                    print(f"**Message:** {finding.get('message', '')}")
                    if finding.get("recommendation"):
                        print(
                            f"**Recommendation:** "
                            f"{finding.get('recommendation', '')}"
                        )
                    print()
        else:
            print("[OK] No issues detected in the network configuration!")
            print()
