---
title: Run network diagnostics on Azure Kubernetes Service (AKS) clusters
description: Learn how to use the Azure CLI aks-net-diagnostics extension to analyze and troubleshoot network configuration issues in AKS clusters.
author: sturrent
ms.author: sturrent
ms.topic: how-to
ms.custom: devx-track-azurecli
ms.date: 12/15/2025
---

Network configuration issues are among the most common causes of problems in Azure Kubernetes Service (AKS) clusters. The `aks-net-diagnostics` Azure CLI extension provides comprehensive, read-only analysis of your AKS cluster's network configuration to help you identify and resolve connectivity issues quickly.

This article shows you how to install and use the AKS network diagnostics extension to analyze DNS configuration, outbound connectivity, network security groups (NSGs), routing, and Private Link resources.

> [!IMPORTANT]
> The `aks-net-diagnostics` extension is currently in **preview**. Features and commands may change in future releases. See the [Supplemental Terms of Use for Microsoft Azure Previews](https://azure.microsoft.com/support/legal/preview-supplemental-terms/) for legal terms that apply to Azure features that are in beta, preview, or otherwise not yet released into general availability.

## Overview

The AKS network diagnostics extension performs read-only analysis of your cluster's network configuration. **It does not modify any resources or configurations** in your AKS cluster or Azure environment. All diagnostics are performed by analyzing existing configurations and resources.

### Scope

This tool primarily focuses on **egress (north-south) connectivity**—traffic flowing from your cluster to external resources such as Azure services, container registries, and the internet. It validates the Azure infrastructure components that enable outbound communication from your AKS cluster.

For **internal cluster (east-west) connectivity** issues between pods or services, this tool provides limited coverage through NSG rule analysis and DNS configuration checks. Pod-to-pod networking issues typically require in-cluster troubleshooting using tools like `kubectl`, network policies inspection, or CNI-specific diagnostics.

The extension analyzes the following areas:

| Diagnostic category | Description |
|---------------------|-------------|
| **DNS resolution** | Validates VNET DNS configuration and private DNS zones (when configured for private clusters) |
| **Outbound connectivity** | Tests cluster internet egress and validates connectivity to required Azure endpoints |
| **Network Security Groups (NSGs)** | Checks NSG rules affecting cluster communication and validates required rules |
| **Routes and routing** | Analyzes route tables and custom routing configurations |
| **Private DNS zones** | Validates private DNS zone configuration for private clusters |
| **Private Link** | Examines Private Link and Private Endpoint configurations |

## Prerequisites

Before you begin, make sure you have the following prerequisites:

- **Azure CLI** version 2.60.0 or later. Run `az --version` to see the currently installed version. If you need to install or upgrade, see [Install Azure CLI](/cli/azure/install-azure-cli).
- **Python** version 3.10 or later.
- **Azure subscription** with an existing AKS cluster to diagnose.
- **Azure RBAC permissions** to read cluster and network resources. See [Required permissions](#required-permissions) for details.

### Required permissions

The diagnostic tool runs using your Azure CLI credentials and requires specific permissions to access cluster and network resources. Depending on your role assignments and the cluster's configuration:

- Some diagnostic checks may be skipped if you lack sufficient permissions.
- The tool clearly indicates which checks were skipped and what permissions are needed.

**Recommended minimum permissions:**

| Permission | Description |
|------------|-------------|
| `Microsoft.ContainerService/managedClusters/read` | Read AKS cluster configuration |
| `Microsoft.Network/*/read` | Read network resources (VNETs, NSGs, route tables, etc.) |
| `Microsoft.Compute/*/read` | Read compute resources (VMs, VMSS) |
| `Microsoft.Network/privateDnsZones/read` | Read private DNS zone configuration |

**Additional permissions for `--probe-test`:**

| Permission | Description |
|------------|-------------|
| `Microsoft.Compute/virtualMachineScaleSets/virtualmachines/runCommand/action` | Run commands on VMSS instances (node pools) |

> [!NOTE]
> The `--probe-test` option requires **Virtual Machine Contributor** permissions on the cluster's node resource group (typically named `MC_<resource-group>_<cluster-name>_<location>`). Without this permission, the probe tests will be skipped.

> [!TIP]
> For complete diagnostics, ensure you have the built-in **Reader** role on the resource group containing the AKS cluster and its associated network resources.

## Install the extension

Install the AKS network diagnostics extension using the Azure CLI:

```azurecli
az extension add --name aks-net-diagnostics
```

Verify the installation:

```azurecli
az extension list --output table
```

To upgrade to the latest version:

```azurecli
az extension add --name aks-net-diagnostics --upgrade
```

## Run network diagnostics

### Basic diagnostics

Run basic network diagnostics on an AKS cluster:

```azurecli
az aks net-diagnostics --resource-group <resource-group-name> --name <cluster-name>
```

Replace `<resource-group-name>` with your resource group name and `<cluster-name>` with your AKS cluster name.

### Get detailed output

Use the `--details` flag to get verbose diagnostic information:

```azurecli
az aks net-diagnostics --resource-group <resource-group-name> --name <cluster-name> --details
```

### Run active connectivity tests

Include active DNS resolution and outbound connectivity tests from cluster nodes using the `--probe-test` flag:

```azurecli
az aks net-diagnostics --resource-group <resource-group-name> --name <cluster-name> --probe-test
```

> [!NOTE]
> The `--probe-test` option runs active connectivity tests from cluster nodes to validate DNS resolution and outbound connectivity to required endpoints. This requires **Virtual Machine Contributor** permissions on the cluster's node resource group.

### Save results to a JSON file

Export diagnostic results to a JSON file while still showing the console report:

```azurecli
az aks net-diagnostics --resource-group <resource-group-name> --name <cluster-name> --json-report output.json
```

### Run full diagnostics

Run complete diagnostics with all options:

```azurecli
az aks net-diagnostics \
    --resource-group <resource-group-name> \
    --name <cluster-name> \
    --details \
    --probe-test \
    --json-report diagnostics-report.json
```

## Understand the results

The diagnostic tool provides results with the following severity levels:

| Severity | Description |
|----------|-------------|
| **INFO** | Informational findings about your cluster configuration |
| **WARNING** | Potential issues that may need attention |
| **ERROR** | Configuration problems that could impact cluster functionality |
| **CRITICAL** | Severe misconfigurations requiring immediate action |

Each finding includes:

- **Category and severity level** - Indicates the diagnostic area and importance
- **Detailed description** - Explains the issue found
- **Affected resources** - Lists resources and their configurations
- **Recommended remediation** - Provides steps to resolve the issue

## Diagnostic categories

### DNS Analyzer

The DNS analyzer checks:

- VNET DNS server configuration
- Private DNS zone validation (for private clusters)
- DNS record verification
- Zone link analysis

### Outbound connectivity analyzer

The outbound connectivity analyzer validates:

- Internet egress configuration
- Connectivity to required Azure endpoints
- Proxy configuration analysis
- NAT gateway configuration

### Network Security Group (NSG) analyzer

The NSG analyzer examines:

- NSG rules affecting AKS cluster communication
- Required rule validation
- Rule priority analysis
- Security recommendations

### Routes analyzer

The routes analyzer checks:

- Route table configuration
- Custom routes analysis
- System routes validation
- Next hop verification

### Private DNS analyzer

The private DNS analyzer (for private clusters) validates:

- Private DNS zone configuration
- A-record validation
- Zone link verification
- VNET integration checks

### Private Link analyzer

The Private Link analyzer examines:

- Private endpoint status
- Private link service configuration
- Connection state validation
- Network interface analysis

## Troubleshooting

### Authentication issues

Ensure you're logged in to Azure CLI:

```azurecli
az login
az account show
```

### Permission issues

If you receive permission errors or see skipped checks, verify you have the [required permissions](#required-permissions). Consider requesting the **Reader** role on the resource group containing your AKS cluster.

### Extension not found

If the extension is not found after installation:

```azurecli
az extension list
az extension add --name aks-net-diagnostics --upgrade
```

## Command reference

### az aks net-diagnostics

Runs comprehensive network diagnostics on an AKS cluster.

```azurecli
az aks net-diagnostics --resource-group <resource-group>
                       --name <cluster-name>
                       [--details]
                       [--probe-test]
                       [--json-report <file-path>]
```

#### Required parameters

| Parameter | Description |
|-----------|-------------|
| `--resource-group`, `-g` | Name of resource group containing the AKS cluster |
| `--name`, `-n` | Name of the AKS cluster |

#### Optional parameters

| Parameter | Description |
|-----------|-------------|
| `--details` | Show detailed diagnostic information |
| `--probe-test` | Run active DNS resolution and outbound connectivity tests from cluster nodes (requires Virtual Machine Contributor permissions) |
| `--json-report` | Path to save JSON diagnostic report |

## Related content

- [AKS networking concepts](/azure/aks/concepts-network)
- [Best practices for network resources in AKS](/azure/aks/operator-best-practices-network)
- [Troubleshoot common AKS network issues](/azure/aks/troubleshooting)
- [Configure Azure CNI networking in AKS](/azure/aks/configure-azure-cni)
- [Configure Azure CNI Overlay networking in AKS](/azure/aks/azure-cni-overlay)
