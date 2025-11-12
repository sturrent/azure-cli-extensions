# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
AKS Network Diagnostics Orchestrator
Adapted from aks-net-diagnostics tool (azure-sdk branch) for Azure CLI integration
"""

import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

from azext_aks_net_diagnostics._version import __version__
from azext_aks_net_diagnostics.api_server_analyzer import (
    APIServerAccessAnalyzer
)
from azext_aks_net_diagnostics.cluster_data_collector import (
    ClusterDataCollector
)
from azext_aks_net_diagnostics.connectivity_tester import (
    ConnectivityTester
)
from azext_aks_net_diagnostics.dns_analyzer import DNSAnalyzer
from azext_aks_net_diagnostics.misconfiguration_analyzer import (
    MisconfigurationAnalyzer
)
from azext_aks_net_diagnostics.models import FindingCode
from azext_aks_net_diagnostics.nsg_analyzer import NSGAnalyzer
from azext_aks_net_diagnostics.outbound_analyzer import (
    OutboundConnectivityAnalyzer
)
from azext_aks_net_diagnostics.report_generator import (
    ReportGenerator
)
from azext_aks_net_diagnostics.route_table_analyzer import (
    RouteTableAnalyzer
)


def _build_subnet_cidr_lookup(vnets_analysis: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    Build subnet ID to CIDR lookup dictionary from VNet analysis results.

    Args:
        vnets_analysis: List of VNet analysis results containing subnet information

    Returns:
        Dictionary mapping lowercase subnet IDs to their CIDR ranges
    """
    subnet_cidrs = {}
    for vnet in vnets_analysis:
        for subnet in vnet.get('subnets', []):
            subnet_id = subnet.get('id', '').lower()
            # Use address_prefix (single) or first from address_prefixes (multiple)
            cidr = subnet.get('address_prefix') or (
                subnet.get('address_prefixes', [None])[0]
                if subnet.get('address_prefixes') else None
            )
            if subnet_id and cidr:
                subnet_cidrs[subnet_id] = cidr
    return subnet_cidrs


def _collect_permission_findings(
    probe_test: bool,
    api_probe_results: Dict[str, Any],
    cluster_info: Dict[str, Any],
    collector,
    outbound_analyzer,
    dns_analyzer,
    logger
) -> List[Dict[str, Any]]:
    """
    Collect and deduplicate permission findings from various analyzers.

    Args:
        probe_test: Whether connectivity tests were requested
        api_probe_results: Results from connectivity tests
        cluster_info: Cluster information dictionary
        collector: ClusterDataCollector instance
        outbound_analyzer: OutboundConnectivityAnalyzer instance
        dns_analyzer: DNSAnalyzer instance
        logger: Logger instance

    Returns:
        List of unique permission findings
    """
    permission_findings = []

    # Check if connectivity tests were skipped due to permissions
    if (probe_test and api_probe_results.get("skipped") and
            "permission" in api_probe_results.get("reason", "").lower()):
        mc_rg = api_probe_results.get("mc_resource_group", "MC_ resource group")
        permission_findings.append({
            "severity": "warning",
            "code": "PERMISSION_INSUFFICIENT_VMSS",
            "message": f"Connectivity tests skipped - Missing permission to run commands on VMSS in {mc_rg}",
            "recommendation": (
                f"Grant the 'Virtual Machine Contributor' role on resource group '{mc_rg}' "
                f"or assign a custom role with the "
                f"'Microsoft.Compute/virtualMachineScaleSets/virtualmachines/runCommand/action' permission "
                f"to run connectivity tests. "
                f"Use: az role assignment create --role 'Virtual Machine Contributor' --assignee <principal-id> "
                f"--scope /subscriptions/<subscription-id>/resourceGroups/{mc_rg}"
            ),
            "details": {
                "resource_type": "VMSS",
                "resource_group": mc_rg,
                "reason": api_probe_results.get("reason"),
                "required_permission": "Microsoft.Compute/virtualMachineScaleSets/virtualmachines/runCommand/action"
            }
        })
        logger.debug("Added connectivity test permission finding (tests skipped)")

    # Check if connectivity tests failed due to runCommand permission errors
    if probe_test and api_probe_results.get("permission_error"):
        mc_rg = cluster_info.get("node_resource_group", "MC_ resource group")
        permission_findings.append({
            "severity": "warning",
            "code": "PERMISSION_INSUFFICIENT_RUNCOMMAND",
            "message": f"Connectivity tests failed - Missing runCommand permission on VMSS in {mc_rg}",
            "recommendation": (
                f"Grant the 'Virtual Machine Contributor' role on resource group '{mc_rg}' "
                f"or assign a custom role with the "
                f"'Microsoft.Compute/virtualMachineScaleSets/virtualmachines/runCommand/action' permission "
                f"to run connectivity tests. "
                f"Use: az role assignment create --role 'Virtual Machine Contributor' --assignee <principal-id> "
                f"--scope /subscriptions/<subscription-id>/resourceGroups/{mc_rg}"
            ),
            "details": {
                "resource_type": "VMSS RunCommand",
                "resource_group": mc_rg,
                "reason": api_probe_results.get("permission_error_reason"),
                "required_permission": "Microsoft.Compute/virtualMachineScaleSets/virtualmachines/runCommand/action"
            }
        })
        logger.debug("Added connectivity test permission finding (runCommand failed)")

    # Collect permission findings from analyzers
    for analyzer, name in [(collector, "cluster data collector"),
                           (outbound_analyzer, "outbound analyzer"),
                           (dns_analyzer, "DNS analyzer")]:
        if hasattr(analyzer, 'findings') and analyzer.findings:
            perm_findings = [f.to_dict() for f in analyzer.findings
                             if f.code.value.startswith('PERMISSION_INSUFFICIENT')]
            if perm_findings:
                logger.debug("Collecting %d permission findings from %s", len(perm_findings), name)
                permission_findings.extend(perm_findings)

    # Deduplicate based on message
    seen_messages = set()
    unique_findings = []
    for finding in permission_findings:
        msg = finding.get('message', '')
        if msg not in seen_messages:
            seen_messages.add(msg)
            unique_findings.append(finding)

    if len(permission_findings) != len(unique_findings):
        logger.debug("Deduplicated permission findings: %d -> %d",
                     len(permission_findings), len(unique_findings))

    return unique_findings


def _enrich_agent_pools_with_vm_subnets(
    agent_pools: List[Dict[str, Any]],
    vm_analysis: List[Dict[str, Any]]
) -> None:
    """
    Enrich agent pool data with subnet information from actual VM NICs.

    For VM node pools, the agent pool profile doesn't include vnet_subnet_id,
    so we need to extract it from the actual VM NICs.

    Args:
        agent_pools: List of agent pool configurations (modified in place)
        vm_analysis: List of VM analysis data with NIC details
    """
    if not vm_analysis:
        return

    # Extract subnet IDs from VM NICs
    vm_subnet_ids = set()
    for vm in vm_analysis:
        nic_details = vm.get("nic_details", [])
        for nic in nic_details:
            ip_configs = nic.get("ip_configurations", [])
            for ip_config in ip_configs:
                subnet = ip_config.get("subnet")
                if subnet:
                    subnet_id = subnet.get("id")
                    if subnet_id:
                        vm_subnet_ids.add(subnet_id)

    # Enrich VM-type agent pools with subnet information
    for pool in agent_pools:
        pool_type = pool.get("type")
        if pool_type == "VirtualMachines":
            # If there's only one subnet used by VMs, assign it to the pool
            if len(vm_subnet_ids) == 1:
                pool["vnet_subnet_id"] = next(iter(vm_subnet_ids))
            elif len(vm_subnet_ids) > 1:
                # Multiple subnets - store them all (though this is unusual)
                pool["vnet_subnet_id"] = next(iter(vm_subnet_ids))  # Use first one for display


def _enrich_agent_pools_with_vmss_subnets(
    agent_pools: List[Dict[str, Any]],
    vmss_analysis: List[Dict[str, Any]]
) -> None:
    """
    Enrich agent pool data with subnet information from VMSS network profiles.

    For VMSS node pools, the agent pool profile may not include vnet_subnet_id
    (especially for overlay networking), so we extract it from the VMSS network profile.

    Args:
        agent_pools: List of agent pool configurations (modified in place)
        vmss_analysis: List of VMSS analysis data with network profiles
    """
    if not vmss_analysis:
        return

    # Build a map from VMSS name to subnet IDs
    vmss_subnet_map = {}
    for vmss in vmss_analysis:
        vmss_name = vmss.get("name", "")
        if not vmss_name:
            continue

        # Extract subnet IDs from VMSS network profile
        network_profile = vmss.get("virtual_machine_profile", {}).get("network_profile", {})
        network_interfaces = network_profile.get("network_interface_configurations", [])

        subnet_ids = set()
        for nic in network_interfaces:
            ip_configs = nic.get("ip_configurations", [])
            for ip_config in ip_configs:
                subnet = ip_config.get("subnet", {})
                subnet_id = subnet.get("id")
                if subnet_id:
                    subnet_ids.add(subnet_id)

        if subnet_ids:
            vmss_subnet_map[vmss_name] = subnet_ids

    # Enrich VMSS-type agent pools with subnet information
    for pool in agent_pools:
        pool_type = pool.get("type")
        if pool_type != "VirtualMachines":  # VMSS or VirtualMachineScaleSets
            # Skip if already has vnet_subnet_id
            if pool.get("vnet_subnet_id"):
                continue

            # Match by pool name to VMSS
            pool_name = pool.get("name", "")
            # VMSS name pattern: aks-{poolname}-{numbers}-vmss
            for vmss_name, subnet_ids in vmss_subnet_map.items():
                if pool_name in vmss_name:
                    # Found matching VMSS
                    if len(subnet_ids) == 1:
                        pool["vnet_subnet_id"] = next(iter(subnet_ids))
                    elif len(subnet_ids) > 1:
                        # Multiple subnets - use first one for display
                        pool["vnet_subnet_id"] = next(iter(subnet_ids))
                    break


def run_diagnostics(  # pylint: disable=too-many-locals
    aks_client,
    agent_pools_client,
    network_client,
    compute_client,
    privatedns_client,
    credential,
    resource_group_name: str,
    cluster_name: str,
    subscription_id: str,
    details: bool = False,
    probe_test: bool = False,
    json_report_path: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
    suppress_console_output: bool = False
) -> Dict[str, Any]:
    """
    Run comprehensive network diagnostics on an AKS cluster.

    This function orchestrates all diagnostic modules to analyze:
    - Cluster configuration
    - VNet and subnet configuration
    - Outbound connectivity
    - Network Security Groups
    - Private DNS configuration
    - API server access
    - Connectivity tests (if probe_test enabled)
    - Misconfigurations

    Args:
        aks_client: ContainerServiceClient for AKS operations
        agent_pools_client: AgentPoolsOperations for agent pool operations
        network_client: NetworkManagementClient for network operations
        compute_client: ComputeManagementClient for VMSS operations
        privatedns_client: PrivateDnsManagementClient for DNS operations
        credential: Azure credential for cross-subscription scenarios
        resource_group_name: Resource group name
        cluster_name: AKS cluster name
        subscription_id: Azure subscription ID
        details: Show detailed output
        probe_test: Enable active connectivity checks (executes commands on nodes)
        json_report_path: Path to save JSON report (if provided)
        logger: Optional logger instance
        suppress_console_output: Suppress console report printing (for json/yaml output)

    Returns:
        Dictionary containing complete diagnostic results

    Raises:
        CLIError: If cluster not found or other validation errors
    """
    # Setup logger if not provided
    if logger is None:
        logger = _setup_logging()

    # Use warning level for progress messages so they show in Azure CLI
    logger.warning("Starting AKS network diagnostics for cluster: %s", cluster_name)

    # Create clients dictionary for analyzers
    clients = {
        "aks_client": aks_client,
        "network_client": network_client,
        "compute_client": compute_client,
        "privatedns_client": privatedns_client,
        "subscription_id": subscription_id,
        "credential": credential
    }

    # Initialize result containers
    findings: List[Dict[str, Any]] = []
    cluster_info: Dict[str, Any] = {}
    agent_pools: List[Dict[str, Any]] = []
    vnets_analysis: List[Dict[str, Any]] = []
    outbound_analysis: Dict[str, Any] = {}
    outbound_ips: List[str] = []
    private_dns_analysis: Dict[str, Any] = {}
    api_server_access_analysis: Dict[str, Any] = {}
    vmss_analysis: List[Dict[str, Any]] = []
    nsg_analysis: Dict[str, Any] = {}
    api_probe_results: Optional[Dict[str, Any]] = None

    # Phase 1: Collect cluster information
    logger.warning("[1/8] Collecting cluster information...")
    collector = ClusterDataCollector(
        aks_client=aks_client,
        agent_pools_client=agent_pools_client,
        network_client=network_client,
        compute_client=compute_client,
        logger=logger
    )
    cluster_data = collector.collect_cluster_info(
        cluster_name,
        resource_group_name
    )
    cluster_info = cluster_data["cluster_info"]
    agent_pools = cluster_data["agent_pools"]

    # Collect node network configuration (VMSS and/or VMs depending on node pool type)
    # This must be done BEFORE VNet analysis so we can enrich agent pools with VM subnet info
    logger.warning("[2/8] Analyzing VNet configuration...")
    logger.warning("  Collecting node network configuration...")
    vmss_analysis = collector.collect_vmss_info(cluster_info)
    vm_analysis = collector.collect_vm_info(cluster_info, agent_pools)

    # Enrich agent pools with subnet information from actual VMs (for VM node pools)
    if vm_analysis:
        _enrich_agent_pools_with_vm_subnets(agent_pools, vm_analysis)

    # Enrich agent pools with subnet information from VMSS network profiles
    if vmss_analysis:
        _enrich_agent_pools_with_vmss_subnets(agent_pools, vmss_analysis)

    # Now analyze VNets with enriched agent pool data
    vnets_analysis = collector.collect_vnet_info(agent_pools)

    # Check if we have permission issues that might affect subsequent analysis
    has_vmss_permission_issues = any(
        f.code in [
            FindingCode.PERMISSION_INSUFFICIENT_VMSS,
            FindingCode.PERMISSION_INSUFFICIENT_VNET
        ]
        for f in collector.findings
    )

    # Phase 3: Analyze User Defined Routes (UDRs)
    logger.warning("[3/8] Analyzing Route Tables (UDRs)...")
    route_table_analyzer = RouteTableAnalyzer(
        agent_pools=agent_pools,
        vmss_analysis=vmss_analysis,
        network_client=clients.get('network_client'),
        logger=logger
    )
    route_table_analysis = route_table_analyzer.analyze()

    # Add note if route table analysis is incomplete due to permissions
    if has_vmss_permission_issues and not route_table_analysis.get("route_tables"):
        route_table_analysis["incomplete_due_to_permissions"] = True
        logger.warning(
            "  Route table analysis may be incomplete due to "
            "insufficient permissions to read VMSS/VNet configuration"
        )

    # Phase 4: Analyze outbound connectivity
    logger.warning("[4/8] Analyzing outbound connectivity...")
    outbound_analyzer = OutboundConnectivityAnalyzer(
        cluster_info=cluster_info,
        agent_pools=agent_pools,
        clients=clients,
        route_table_analysis=route_table_analysis,
        vmss_info=vmss_analysis,
        logger=logger
    )
    outbound_analysis = outbound_analyzer.analyze(show_details=details)
    outbound_ips = outbound_analyzer.get_outbound_ips()

    # Add UDR analysis to outbound analysis (expected by misconfiguration analyzer)
    outbound_analysis["udr_analysis"] = route_table_analysis

    # Phase 5: Analyze Network Security Groups
    logger.warning("[5/8] Analyzing Network Security Groups...")
    nsg_analyzer = NSGAnalyzer(
        clients=clients,
        cluster_info=cluster_info,
        vmss_info=vmss_analysis,
        vm_info=vm_analysis,
        logger=logger
    )
    nsg_analysis = nsg_analyzer.analyze()

    # Add note if NSG analysis is incomplete due to permissions
    if has_vmss_permission_issues and nsg_analysis.get("nsgs_analyzed", 0) == 0:
        nsg_analysis["incomplete_due_to_permissions"] = True
        logger.warning(
            "  NSG analysis may be incomplete due to "
            "insufficient permissions to read VMSS/VNet configuration"
        )

    # Phase 6: Analyze DNS configuration
    logger.warning("[6/8] Analyzing DNS configuration...")
    dns_analyzer = DNSAnalyzer(clients=clients, cluster_info=cluster_info, logger=logger)
    private_dns_analysis = dns_analyzer.analyze()

    # Phase 7: Analyze API server access
    logger.warning("[7/8] Analyzing API server access configuration...")
    api_server_analyzer = APIServerAccessAnalyzer(
        cluster_info=cluster_info,
        outbound_ips=outbound_ips,
        outbound_analysis=outbound_analysis,
        logger=logger
    )
    api_server_access_analysis = api_server_analyzer.analyze()

    # Phase 8: Run connectivity tests (if enabled)
    if probe_test:
        logger.warning("[8/8] Running connectivity tests (probe mode enabled)...")
        connectivity_tester = ConnectivityTester(
            cluster_info=cluster_info,
            clients=clients,
            dns_analyzer=dns_analyzer,
            show_details=details,
            logger=logger
        )
        api_probe_results = connectivity_tester.test_connectivity(
            enable_probes=True
        )
    else:
        logger.warning(
            "[8/8] Skipping connectivity tests "
            "(use --probe-test to enable)"
        )
        api_probe_results = {"skipped": True, "reason": "Not requested"}

    # Phase 9: Analyze misconfigurations and generate findings
    logger.warning("Analyzing potential misconfigurations...")

    # Collect permission findings from data collection phase
    permission_findings = _collect_permission_findings(
        probe_test=probe_test,
        api_probe_results=api_probe_results,
        cluster_info=cluster_info,
        collector=collector,
        outbound_analyzer=outbound_analyzer,
        dns_analyzer=dns_analyzer,
        logger=logger
    )

    # Run misconfiguration analysis with permission findings context
    misconfiguration_analyzer = MisconfigurationAnalyzer(
        clients=clients,
        logger=logger
    )
    findings, _ = misconfiguration_analyzer.analyze(
        cluster_info=cluster_info,
        outbound_analysis=outbound_analysis,
        outbound_ips=outbound_ips,
        private_dns_analysis=private_dns_analysis,
        api_server_access_analysis=api_server_access_analysis,
        nsg_analysis=nsg_analysis,
        api_probe_results=api_probe_results,
        vmss_analysis=vmss_analysis,
        permission_findings=permission_findings
    )

    # Add permission findings to the final findings list
    findings.extend(permission_findings)

    # Collect findings from individual analyzers
    # DNS analyzer creates findings via add_finding() but they're not
    # included in misconfiguration_analyzer's findings
    # Exclude permission findings as they were already added above
    if hasattr(dns_analyzer, 'findings') and dns_analyzer.findings:
        non_perm_findings = [f.to_dict() for f in dns_analyzer.findings
                             if not f.code.value.startswith('PERMISSION_INSUFFICIENT')]
        if non_perm_findings:
            logger.debug("Collecting %d non-permission findings from DNS analyzer", len(non_perm_findings))
            findings.extend(non_perm_findings)

    if hasattr(nsg_analyzer, 'findings') and nsg_analyzer.findings:
        non_perm_findings = [f.to_dict() for f in nsg_analyzer.findings
                             if not f.code.value.startswith('PERMISSION_INSUFFICIENT')]
        if non_perm_findings:
            logger.debug("Collecting %d non-permission findings from NSG analyzer", len(non_perm_findings))
            findings.extend(non_perm_findings)

    # Phase 10: Generate report
    logger.info("Generating diagnostic report...")

    # Build subnet CIDR lookup dict from vnets_analysis
    subnet_cidrs = _build_subnet_cidr_lookup(vnets_analysis)
    logger.debug("Built subnet CIDR lookup with %d entries", len(subnet_cidrs))

    report_generator = ReportGenerator(
        cluster_name=cluster_name,
        resource_group=resource_group_name,
        subscription=subscription_id,
        cluster_info=cluster_info,
        agent_pools=agent_pools,
        findings=findings,
        vnets_analysis=vnets_analysis,
        route_table_analysis=route_table_analysis,
        outbound_analysis=outbound_analysis,
        outbound_ips=outbound_ips,
        private_dns_analysis=private_dns_analysis,
        api_server_access_analysis=api_server_access_analysis,
        vmss_analysis=vmss_analysis,
        vm_analysis=vm_analysis,
        nsg_analysis=nsg_analysis,
        api_probe_results=api_probe_results,
        script_version=__version__,
        subnet_cidrs=subnet_cidrs,
        logger=logger
    )

    # Generate JSON report data once
    result = report_generator.generate_json_report()

    # Save JSON report if requested
    if json_report_path:
        try:
            with open(json_report_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            os.chmod(json_report_path, 0o600)
            logger.info("[DOC] JSON report saved to: %s", json_report_path)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Failed to save JSON report: %s", e)

    # Print console report (unless suppressed for json/yaml output)
    if not suppress_console_output:
        report_generator.print_console_report(
            show_details=details,
            json_report_path=json_report_path
        )

    logger.info("Diagnostic analysis complete")

    return result


def _setup_logging() -> logging.Logger:
    """
    Configure logging with appropriate handlers and formatters.

    Returns:
        Configured logger instance
    """
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    logger = logging.getLogger("aks_net_diagnostics")
    logger.propagate = False

    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    logger.setLevel(logging.INFO)

    return logger
