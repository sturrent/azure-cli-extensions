# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------


def load_arguments(self, _):
    with self.argument_context('aks net-diagnostics') as c:
        c.argument('resource_group_name', options_list=['--resource-group', '-g'],
                   help='Name of resource group. You can configure the default group using '
                        '`az configure --defaults group=<name>`')
        c.argument('name', options_list=['--name', '-n'],
                   help='Name of the managed cluster.')
        c.argument('details', options_list=['--details'],
                   action='store_true',
                   help='Show detailed diagnostic information including full network '
                        'configuration analysis.')
        c.argument('probe_test', options_list=['--probe-test'],
                   action='store_true',
                   help='Enable active connectivity tests from cluster nodes. Requires '
                        'Virtual Machine Contributor permissions.')
        c.argument('json_report', options_list=['--json-report'],
                   help='Path to save JSON diagnostic report.')
