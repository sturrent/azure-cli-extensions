# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from knack.help_files import helps


helps['aks net-diagnostics'] = """
    type: command
    short-summary: Run comprehensive read-only network diagnostics on an AKS cluster.
    long-summary: |
        Performs read-only analysis of AKS cluster network configuration including:
        - DNS resolution (VNET DNS configuration and private DNS zones)
        - Outbound connectivity to required endpoints
        - Network Security Groups (NSGs)
        - Routes and routing tables
        - Private DNS zones (for private clusters)
        - Private Link resources

        This tool does NOT modify any resources - all diagnostics are read-only analysis.

        The tool runs using your Azure CLI credentials. Diagnostic checks may be skipped
        if you lack sufficient permissions, with clear indication of required roles in the output.

        This command is currently in preview and may change in future releases.
    examples:
        - name: Run basic network diagnostics on an AKS cluster
          text: az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster
        - name: Run diagnostics with detailed output
          text: az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --details
        - name: Run diagnostics and save results as JSON
          text: az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --json-report output.json
        - name: Run diagnostics with active connectivity tests from cluster nodes
          text: az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --probe-test
        - name: Run full diagnostics with all options
          text: |
            az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster \\
                --details --probe-test --json-report diagnostics-report.json
"""
