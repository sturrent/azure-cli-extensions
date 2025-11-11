# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core.commands.client_factory import get_mgmt_service_client


def cf_managed_clusters(cli_ctx, *_):
    from azure.mgmt.containerservice import ContainerServiceClient
    return get_mgmt_service_client(cli_ctx, ContainerServiceClient).managed_clusters


def cf_agent_pools(cli_ctx, *_):
    from azure.mgmt.containerservice import ContainerServiceClient
    return get_mgmt_service_client(cli_ctx, ContainerServiceClient).agent_pools


def cf_network_client(cli_ctx, subscription_id=None):
    from azure.mgmt.network import NetworkManagementClient
    return get_mgmt_service_client(cli_ctx, NetworkManagementClient, subscription_id=subscription_id)


def cf_compute_client(cli_ctx, subscription_id=None):
    from azure.mgmt.compute import ComputeManagementClient
    return get_mgmt_service_client(cli_ctx, ComputeManagementClient, subscription_id=subscription_id)


def cf_privatedns_client(cli_ctx, subscription_id=None):
    from azure.mgmt.privatedns import PrivateDnsManagementClient
    return get_mgmt_service_client(cli_ctx, PrivateDnsManagementClient, subscription_id=subscription_id)
