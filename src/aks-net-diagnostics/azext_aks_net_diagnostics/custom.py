# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from knack.log import get_logger
from azext_aks_net_diagnostics._client_factory import (
    cf_network_client,
    cf_compute_client,
    cf_privatedns_client,
    cf_agent_pools
)
from azext_aks_net_diagnostics.orchestrator import run_diagnostics

logger = get_logger(__name__)


def aks_net_diagnostics(cmd, client, resource_group_name, name,
                        details=False, probe_test=False, json_report=None):
    """
    Run comprehensive network diagnostics on an AKS cluster.

    Args:
        cmd: Command context
        client: ManagedClustersOperations client
        resource_group_name: Resource group name
        name: AKS cluster name
        details: Show detailed output
        probe_test: Enable active connectivity tests
        json_report: Path to save JSON report

    Returns:
        Diagnostic results dictionary
    """
    from azure.cli.core._profile import Profile

    # Get subscription ID from CLI context
    profile = Profile(cli_ctx=cmd.cli_ctx)
    subscription_id = profile.get_subscription_id()

    # Get credential
    credential = profile.get_login_credentials()[0]

    # Get required clients
    aks_client = client
    agent_pools_client = cf_agent_pools(cmd.cli_ctx)
    network_client = cf_network_client(cmd.cli_ctx)
    compute_client = cf_compute_client(cmd.cli_ctx)
    privatedns_client = cf_privatedns_client(cmd.cli_ctx)

    # Run diagnostics
    result = run_diagnostics(
        aks_client=aks_client,
        agent_pools_client=agent_pools_client,
        network_client=network_client,
        compute_client=compute_client,
        privatedns_client=privatedns_client,
        credential=credential,
        resource_group_name=resource_group_name,
        cluster_name=name,
        subscription_id=subscription_id,
        details=details,
        probe_test=probe_test,
        json_report_path=json_report,
        logger=logger
    )

    return result
