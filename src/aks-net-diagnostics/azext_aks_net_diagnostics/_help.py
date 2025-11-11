# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from knack.help_files import helps


helps['aks net-diagnostics'] = """
    type: command
    short-summary: Run comprehensive network diagnostics on an AKS cluster.
    long-summary: |
        Analyzes AKS cluster network configuration including:
        - DNS resolution (CoreDNS and host DNS)
        - Outbound connectivity
        - Load balancer health probes
        - Network Security Groups (NSGs)
        - Routes and routing tables
        - Private DNS zones
        - Private Link resources

        The diagnostic tool identifies common network misconfigurations and provides
        actionable recommendations to resolve issues.

        This command is currently in preview and may change in future releases.
    examples:
        - name: Run basic network diagnostics on an AKS cluster
          text: az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster
        - name: Run diagnostics with detailed output
          text: az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --details
        - name: Run diagnostics and save results as JSON
          text: az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --json-report output.json
        - name: Run diagnostics including health probe tests
          text: az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --probe-test
        - name: Run full diagnostics with all options
          text: |
            az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster \\
                --details --probe-test --json-report diagnostics-report.json
"""
