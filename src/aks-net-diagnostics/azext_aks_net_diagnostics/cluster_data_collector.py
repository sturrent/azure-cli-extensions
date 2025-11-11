# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
Cluster Data Collector for AKS Network Diagnostics

This module handles fetching and collecting cluster-related data from Azure,
including cluster information, agent pools, VNets, and VMSS configurations.

Adapted for Azure CLI - uses pre-authenticated SDK clients.
"""

import logging
import re
from typing import Any, Dict, List, Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

from .models import Finding, FindingCode, Severity


def _to_dict(obj: Any) -> Any:
    """
    Convert Azure SDK object to dictionary recursively.

    Args:
        obj: Azure SDK object or primitive type

    Returns:
        Dictionary representation or primitive value
    """
    if hasattr(obj, 'as_dict'):
        return obj.as_dict()
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_dict(item) for item in obj]
    return obj


class ClusterDataCollector:
    """Collects cluster information and related Azure resources using Azure SDK."""

    def __init__(
        self,
        aks_client,
        agent_pools_client,
        network_client,
        compute_client,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize ClusterDataCollector.

        Args:
            aks_client: Authenticated ContainerServiceClient
            agent_pools_client: Authenticated AgentPoolsOperations client
            network_client: Authenticated NetworkManagementClient
            compute_client: Authenticated ComputeManagementClient
            logger: Optional logger instance. If not provided, creates a default logger.
        """
        self.aks_client = aks_client
        self.agent_pools_client = agent_pools_client
        self.network_client = network_client
        self.compute_client = compute_client
        self.logger = logger or logging.getLogger(__name__)
        self.findings: List[Finding] = []

    def _check_authorization_error(
        self,
        error: HttpResponseError,
        resource_type: str,
        resource_name: str,
        resource_group: Optional[str] = None
    ) -> bool:
        """
        Check if the error is an authorization failure and create a finding.

        Args:
            error: The HttpResponseError to check
            resource_type: Type of resource (e.g., 'VNet', 'VMSS', 'LoadBalancer')
            resource_name: Name of the resource
            resource_group: Optional resource group name

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

            # Determine finding code based on resource type
            code_map = {
                'VNet': FindingCode.PERMISSION_INSUFFICIENT_VNET,
                'VMSS': FindingCode.PERMISSION_INSUFFICIENT_VMSS,
                'LoadBalancer': FindingCode.PERMISSION_INSUFFICIENT_LB,
            }
            finding_code = code_map.get(resource_type, FindingCode.PERMISSION_INSUFFICIENT_VNET)

            # Build recommendation message
            rg_info = f" on resource group '{resource_group}'" if resource_group else ""
            recommendation = (
                f"Grant the 'Reader' role{rg_info} or assign a role with the "
                f"'{missing_permission}' permission to access {resource_type} resources. "
                f"Use: az role assignment create --role Reader --assignee <principal-id> "
                f"--scope /subscriptions/<subscription-id>/resourceGroups/{resource_group or '<resource-group>'}"
            )

            # Create finding
            finding = Finding(
                severity=Severity.WARNING,
                code=finding_code,
                message=f"Incomplete {resource_type} Analysis - Missing permission to read {resource_name}",
                recommendation=recommendation,
                details={
                    'resource_type': resource_type,
                    'resource_name': resource_name,
                    'resource_group': resource_group,
                    'missing_permission': missing_permission,
                    'error': error_message
                }
            )
            self.findings.append(finding)
            self.logger.warning("  %s", finding.message)
            return True

        return False

    def collect_cluster_info(self, cluster_name: str, resource_group: str) -> Dict[str, Any]:
        """
        Fetch basic cluster information and agent pools.

        Args:
            cluster_name: Name of the AKS cluster
            resource_group: Resource group containing the cluster

        Returns:
            Dictionary containing:
                - cluster_info: Cluster configuration details
                - agent_pools: List of node pool configurations

        Raises:
            ValueError: If cluster information cannot be retrieved
        """
        self.logger.info("Fetching cluster information...")

        try:
            # Get cluster info using SDK
            cluster = self.aks_client.get(resource_group, cluster_name)
            cluster_result = _to_dict(cluster)

            # Extract error details from status if available
            if hasattr(cluster, "status") and cluster.status:
                if hasattr(cluster.status, "additional_properties") and cluster.status.additional_properties:
                    if "status" not in cluster_result:
                        cluster_result["status"] = {}
                    cluster_result["status"].update(_to_dict(cluster.status.additional_properties))
                if hasattr(cluster.status, "provisioning_error") and cluster.status.provisioning_error:
                    if "status" not in cluster_result:
                        cluster_result["status"] = {}
                    cluster_result["status"]["provisioning_error"] = cluster.status.provisioning_error

        except ResourceNotFoundError as exc:
            raise ValueError(
                f"Cluster '{cluster_name}' not found in resource group '{resource_group}'. "
                f"Please check the cluster name and resource group."
            ) from exc
        except HttpResponseError as e:
            raise ValueError(
                f"Failed to get cluster information for {cluster_name}: {e.message}"
            ) from e

        if not cluster_result or not isinstance(cluster_result, dict):
            raise ValueError(
                f"Failed to get cluster information for {cluster_name}'. "
                f"Please check the cluster name and resource group."
            )

        # Get agent pools from cluster's agent_pool_profiles
        # This provides the correct 'type' field (VirtualMachines vs VirtualMachineScaleSets)
        # as opposed to agent_pools_client.list() which returns ARM resource type
        agent_pools = cluster_result.get("agent_pool_profiles", [])

        if not agent_pools:
            self.logger.warning("No agent pools found in cluster configuration")

        return {"cluster_info": cluster_result, "agent_pools": agent_pools}

    def collect_vnet_info(self, agent_pools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Collect VNet configuration from agent pools.

        Args:
            agent_pools: List of agent pool configurations

        Returns:
            List of VNet analysis results containing VNet details and peerings
        """
        self.logger.info("Analyzing VNet configuration...")

        # Get unique subnet IDs from agent pools
        subnet_ids = set()
        for pool in agent_pools:
            subnet_id = pool.get("vnet_subnet_id")
            if subnet_id and subnet_id != "null":
                subnet_ids.add(subnet_id)

        if not subnet_ids:
            self.logger.info(
                "Agent pools use AKS-managed VNet (vnet_subnet_id not set). "
                "VNet details will be retrieved from VMSS configuration."
            )
            return []

        # Analyze each VNet
        vnets_map = {}
        for subnet_id in subnet_ids:
            if not subnet_id:
                continue

            # Extract VNet info from subnet ID
            vnet_match = re.search(r"/virtualNetworks/([^/]+)", subnet_id)
            if not vnet_match:
                continue

            vnet_name = vnet_match.group(1)
            vnet_rg = subnet_id.split("/")[4]  # Resource group is at index 4

            if vnet_name not in vnets_map:
                try:
                    # Get VNet information
                    vnet = self.network_client.virtual_networks.get(vnet_rg, vnet_name)

                    vnets_map[vnet_name] = {
                        "name": vnet_name,
                        "resource_group": vnet_rg,
                        "id": vnet.id,
                        "address_space": vnet.address_space.address_prefixes if vnet.address_space else [],
                        "subnets": [],
                        "peerings": [],
                    }

                    # Collect subnet details with CIDR information
                    if vnet.subnets:
                        for subnet in vnet.subnets:
                            addr_prefixes = (subnet.address_prefixes
                                             if hasattr(subnet, 'address_prefixes')
                                             else None)
                            vnets_map[vnet_name]["subnets"].append({
                                "id": subnet.id,
                                "name": subnet.name,
                                "address_prefix": subnet.address_prefix,
                                "address_prefixes": addr_prefixes,
                            })

                    # Get VNet peerings
                    peerings_list = list(
                        self.network_client.virtual_network_peerings.list(vnet_rg, vnet_name)
                    )

                    for peering in peerings_list:
                        vnets_map[vnet_name]["peerings"].append(
                            {
                                "name": peering.name,
                                "remote_virtual_network": (
                                    peering.remote_virtual_network.id
                                    if peering.remote_virtual_network
                                    else ""
                                ),
                                "peering_state": peering.peering_state,
                                "allow_virtual_network_access": peering.allow_virtual_network_access,
                                "allow_forwarded_traffic": peering.allow_forwarded_traffic,
                                "allow_gateway_transit": peering.allow_gateway_transit,
                                "use_remote_gateways": peering.use_remote_gateways,
                            }
                        )

                except (ResourceNotFoundError, HttpResponseError) as e:
                    # Check if this is an authorization error
                    if isinstance(e, HttpResponseError):
                        if self._check_authorization_error(e, 'VNet', vnet_name, vnet_rg):
                            continue  # Authorization error, finding already created
                    self.logger.warning("Failed to retrieve VNet %s: %s", vnet_name, e)
                    continue

        return list(vnets_map.values())

    def collect_vmss_info(self, cluster_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Collect VMSS network configuration from the managed resource group.

        Args:
            cluster_info: Cluster configuration dictionary

        Returns:
            List of VMSS details with network profiles
        """
        self.logger.info("Collecting node network configuration (VMSS)...")

        mc_rg = cluster_info.get("node_resource_group", "")
        if not mc_rg:
            self.logger.warning("No managed resource group found in cluster info")
            return []

        try:
            # List VMSS in the managed resource group
            vmss_list = list(self.compute_client.virtual_machine_scale_sets.list(mc_rg))
        except (ResourceNotFoundError, HttpResponseError) as e:
            # Check if this is an authorization error
            if isinstance(e, HttpResponseError):
                if self._check_authorization_error(e, 'VMSS', mc_rg, mc_rg):
                    return []  # Authorization error, finding already created
            self.logger.warning("Failed to list VMSS in %s: %s", mc_rg, e)
            return []

        vmss_analysis = []
        for vmss in vmss_list:
            vmss_name = vmss.name
            if not vmss_name:
                continue

            self.logger.info("  - Analyzing VMSS: %s", vmss_name)

            try:
                # Get VMSS details
                vmss_detail = self.compute_client.virtual_machine_scale_sets.get(mc_rg, vmss_name)
                vmss_detail_dict = _to_dict(vmss_detail)

                network_profile = vmss_detail_dict.get("virtual_machine_profile", {}).get(
                    "network_profile", {}
                )
                network_interfaces = network_profile.get("network_interface_configurations", [])

                # Collect unique subnets for this VMSS
                unique_subnets = set()
                for nic in network_interfaces:
                    ip_configs = nic.get("ip_configurations", [])
                    for ip_config in ip_configs:
                        subnet = ip_config.get("subnet", {})
                        if subnet and subnet.get("id"):
                            subnet_name = subnet["id"].split("/")[-1]
                            unique_subnets.add(subnet_name)

                # Log unique subnets
                for subnet_name in sorted(unique_subnets):
                    self.logger.info("    Found subnet: %s", subnet_name)

                vmss_analysis.append(vmss_detail_dict)

            except (ResourceNotFoundError, HttpResponseError) as e:
                # Check if this is an authorization error
                if isinstance(e, HttpResponseError):
                    if self._check_authorization_error(e, 'VMSS', vmss_name, mc_rg):
                        continue  # Authorization error, finding already created
                self.logger.warning("Failed to get details for VMSS %s: %s", vmss_name, e)
                continue

        return vmss_analysis

    def _collect_vm_nic_details(self, network_interfaces: List[Dict[str, Any]], mc_rg: str) -> tuple:
        """
        Collect detailed NIC information for a VM.

        Args:
            network_interfaces: List of NIC references from VM network profile
            mc_rg: Managed resource group name

        Returns:
            Tuple of (nic_details_list, unique_subnets)
        """
        unique_subnets = set()
        nic_details_list = []

        for nic in network_interfaces:
            nic_id = nic.get("id", "")
            if not nic_id:
                continue

            # Parse NIC resource ID
            nic_rg = nic_id.split("/")[4] if len(nic_id.split("/")) > 4 else mc_rg
            nic_name = nic_id.split("/")[-1]

            try:
                nic_detail = self.network_client.network_interfaces.get(nic_rg, nic_name)
                nic_detail_dict = _to_dict(nic_detail)
                nic_details_list.append(nic_detail_dict)

                # Collect subnets from IP configurations
                for ip_config in nic_detail.ip_configurations:
                    if ip_config.subnet:
                        subnet_name = ip_config.subnet.id.split("/")[-1]
                        unique_subnets.add(subnet_name)
            except (ResourceNotFoundError, HttpResponseError) as e:
                self.logger.warning("Failed to get NIC details for %s: %s", nic_name, e)

        return nic_details_list, unique_subnets

    def collect_vm_info(
        self, cluster_info: Dict[str, Any], agent_pools: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Collect VM network configuration from the managed resource group.

        For node pools using Virtual Machines (not VMSS), this method collects
        individual VM details including network interfaces and configurations.

        Args:
            cluster_info: Cluster configuration dictionary
            agent_pools: List of agent pool configurations

        Returns:
            List of VM details with network profiles
        """
        # Check if any agent pools use Virtual Machines
        has_vm_pools = any(
            pool.get("type") == "VirtualMachines" for pool in agent_pools
        )

        if not has_vm_pools:
            # No VM pools, skip silently
            return []

        self.logger.info("Collecting node network configuration (VMs)...")

        mc_rg = cluster_info.get("node_resource_group", "")
        if not mc_rg:
            self.logger.warning("No managed resource group found in cluster info")
            return []

        try:
            # List VMs in the managed resource group
            vm_list = list(self.compute_client.virtual_machines.list(mc_rg))
        except (ResourceNotFoundError, HttpResponseError) as e:
            # Check if this is an authorization error
            if isinstance(e, HttpResponseError):
                if self._check_authorization_error(e, 'VM', mc_rg, mc_rg):
                    return []  # Authorization error, finding already created
            self.logger.warning("Failed to list VMs in %s: %s", mc_rg, e)
            return []

        vm_analysis = []
        for vm in vm_list:
            vm_name = vm.name
            if not vm_name:
                continue

            self.logger.info("  - Analyzing VM: %s", vm_name)

            try:
                # Get VM details
                vm_detail = self.compute_client.virtual_machines.get(
                    mc_rg, vm_name, expand='instanceView'
                )
                vm_detail_dict = _to_dict(vm_detail)

                # Extract network interfaces and get full NIC details
                network_profile = vm_detail_dict.get("network_profile", {})
                network_interfaces = network_profile.get("network_interfaces", [])

                # Collect NIC details using helper method (reduces nesting)
                nic_details_list, unique_subnets = self._collect_vm_nic_details(
                    network_interfaces, mc_rg
                )

                # Log unique subnets
                for subnet_name in sorted(unique_subnets):
                    self.logger.info("    Found subnet: %s", subnet_name)

                # Store full NIC details in the VM dict for NSG analysis
                vm_detail_dict["nic_details"] = nic_details_list
                vm_analysis.append(vm_detail_dict)

            except (ResourceNotFoundError, HttpResponseError) as e:
                # Check if this is an authorization error
                if isinstance(e, HttpResponseError):
                    if self._check_authorization_error(e, 'VM', vm_name, mc_rg):
                        continue  # Authorization error, finding already created
                self.logger.warning("Failed to get details for VM %s: %s", vm_name, e)
                continue

        return vm_analysis

    def collect_all(self, cluster_name: str, resource_group: str) -> Dict[str, Any]:
        """
        Collect all cluster data in one call.

        Args:
            cluster_name: Name of the AKS cluster
            resource_group: Resource group containing the cluster

        Returns:
            Dictionary containing:
                - cluster_info: Cluster configuration details
                - agent_pools: List of node pool configurations
                - vnets_analysis: List of VNet details and peerings
                - vmss_analysis: List of VMSS network configurations
                - vm_analysis: List of VM network configurations (for VM node pools)

        Raises:
            ValueError: If cluster information cannot be retrieved
        """
        # Collect cluster info and agent pools
        cluster_data = self.collect_cluster_info(cluster_name, resource_group)
        cluster_info = cluster_data["cluster_info"]
        agent_pools = cluster_data["agent_pools"]

        # Collect VNet information
        vnets_analysis = self.collect_vnet_info(agent_pools)

        # Collect VMSS information
        vmss_analysis = self.collect_vmss_info(cluster_info)

        # Collect VM information (for Virtual Machines node pools)
        vm_analysis = self.collect_vm_info(cluster_info, agent_pools)

        return {
            "cluster_info": cluster_info,
            "agent_pools": agent_pools,
            "vnets_analysis": vnets_analysis,
            "vmss_analysis": vmss_analysis,
            "vm_analysis": vm_analysis,
        }
