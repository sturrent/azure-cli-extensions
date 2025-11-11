# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core.commands import CliCommandType
from azext_aks_net_diagnostics._client_factory import cf_managed_clusters


def load_command_table(self, _):
    managed_clusters_sdk = CliCommandType(
        operations_tmpl='azure.mgmt.containerservice.operations#ManagedClustersOperations.{}',
        client_factory=cf_managed_clusters
    )

    with self.command_group('aks net-diagnostics', managed_clusters_sdk,
                            client_factory=cf_managed_clusters) as g:
        g.custom_command('', 'aks_net_diagnostics')
