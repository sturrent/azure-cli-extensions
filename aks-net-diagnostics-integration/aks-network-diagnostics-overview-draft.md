---
title: Run network diagnostics on Azure Kubernetes Service (AKS) clusters
description: Learn how to use the Azure CLI aks-net-diagnostics extension to analyze and troubleshoot network configuration issues in AKS clusters.
author: sturrent
ms.author: sturrent
ms.topic: how-to
ms.custom: devx-track-azurecli
ms.date: 04/13/2026
---

Network configuration issues are among the most common causes of problems in Azure Kubernetes Service (AKS) clusters. The `aks-net-diagnostics` Azure CLI extension provides comprehensive, read-only analysis of your AKS cluster's network configuration to help you identify and resolve connectivity issues quickly.

This article shows you how to install and use the AKS network diagnostics extension to analyze DNS configuration, outbound connectivity, network security groups (NSGs), routing, API server access, and private DNS resources. The extension supports standard, private, network-isolated, and proxy-configured clusters.

> [!IMPORTANT]
> The `aks-net-diagnostics` extension is currently in **preview**. Features and commands may change in future releases. See the [Supplemental Terms of Use for Microsoft Azure Previews](https://azure.microsoft.com/support/legal/preview-supplemental-terms/) for legal terms that apply to Azure features that are in beta, preview, or otherwise not yet released into general availability.

## Overview

The AKS network diagnostics extension performs read-only analysis of your cluster's network configuration. **It does not modify any resources or configurations** in your AKS cluster or Azure environment. All diagnostics are performed by analyzing existing configurations and resources.

### Scope

This tool primarily focuses on **egress (north-south) connectivity**—traffic flowing from your cluster to external resources such as Azure services, container registries, and the internet. It validates the Azure infrastructure components that enable outbound communication from your AKS cluster, including network-isolated clusters (outbound type `none` or `block`) and clusters configured with an HTTP proxy.

For **internal cluster (east-west) connectivity** issues between pods or services, this tool provides limited coverage through NSG rule analysis and DNS configuration checks. Pod-to-pod networking issues typically require in-cluster troubleshooting using tools like `kubectl`, network policies inspection, or CNI-specific diagnostics.

The extension analyzes the following areas:

| Diagnostic category | Description |
|---------------------|-------------|
| **DNS resolution** | Validates VNet DNS configuration and private DNS zones (including bootstrap ACR DNS for network-isolated clusters) |
| **Outbound connectivity** | Analyzes outbound type (load balancer, NAT gateway, UDR, `none`, `block`), bootstrap ACR, HTTP proxy configuration, and `defaultOutboundAccess` |
| **Network Security Groups (NSGs)** | Checks NSG rules for required AKS traffic (MCR, AzureCloud, DNS), proxy traffic rules, inter-node communication, service tag semantics, and Azure CNI Overlay pod CIDR rules |
| **Routes and routing** | Analyzes route tables and UDR impact on outbound traffic (firewall/NVA, VPN gateway) |
| **API server access** | Validates authorized IP ranges, service tag usage, private cluster and VNet integration configuration |
| **Private DNS zones** | Validates private DNS zone configuration and VNet links for private clusters |
| **Active connectivity tests** | Optional probe tests: DNS resolution and HTTPS connectivity to MCR, bootstrap ACR, API server, and HTTP proxy from cluster nodes (VMSS and VM node pools) |
| **Cross-component correlation** | Detects composite issues: cluster/node pool provisioning failures, bootstrap ACR DNS link gaps, NSG + outbound + DNS interactions |
| **Node Auto Provisioning (NAP)** | Identifies NAP-enabled clusters and detects Karpenter-managed VMs and VMSS |

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
| `Microsoft.Compute/virtualMachines/runCommand/action` | Run commands on VM-based node pools (VirtualMachines type) |

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
> The `--probe-test` option runs active connectivity tests from cluster nodes (both VMSS and VM-based node pools) to validate DNS resolution and outbound connectivity to required endpoints. For network-isolated clusters, tests target the bootstrap ACR instead of MCR. For proxy-configured clusters, proxy connectivity is also tested. This requires **Virtual Machine Contributor** permissions on the cluster's node resource group.

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
| **CRITICAL** | Severe misconfigurations requiring immediate action |

Each finding includes:

- **Category and severity level** - Indicates the diagnostic area and importance
- **Detailed description** - Explains the issue found
- **Affected resources** - Lists resources and their configurations
- **Recommended remediation** - Provides steps to resolve the issue

## Diagnostic categories

### DNS analyzer

The DNS analyzer checks:

- VNet DNS server configuration (Azure default vs custom DNS)
- Private DNS zone validation for private clusters
- VNet link verification (including cross-subscription BYO DNS zones)
- DNS server VNet hosting and reachability

### Outbound connectivity analyzer

The outbound connectivity analyzer validates:

- Outbound type: `loadBalancer`, `managedNATGateway`, `userAssignedNATGateway`, `userDefinedRouting`, `none`, `block`
- Load balancer frontend IPs, NAT gateway public IPs, and outbound rules
- Network-isolated clusters (`none`/`block`): bootstrap ACR presence and configuration
- HTTP proxy: detection, VNet reachability via peering, proxy IP/port extraction
- `defaultOutboundAccess` subnet-level awareness
- UDR impact on outbound traffic path

### Network Security Group (NSG) analyzer

The NSG analyzer examines:

- Required AKS outbound rules (MCR, AzureCloud, DNS) with adapted rule sets for network-isolated clusters
- HTTP proxy NSG compliance (`AKS_HTTP_Proxy` rule, proxy traffic blocking detection)
- Inter-node communication rules
- Blocking rules and override detection
- Service tag semantics
- Azure CNI Overlay pod CIDR traffic rules
- NSGs on subnets and individual NICs

### Route table analyzer

The route table analyzer checks:

- Default route (0.0.0.0/0) presence and next-hop type
- Routes to `VirtualAppliance` (firewall/NVA) or `VirtualNetworkGateway`
- Impact on AKS management and outbound traffic

### API server access analyzer

The API server access analyzer validates:

- Public vs private cluster setup
- VNet integration detection
- Authorized IP ranges (CIDRs and service tags), validating cluster outbound IPs are included
- Service tag detection, multiple-tag warnings, VNet Integration compatibility
- UDR override detection (firewall/NVA may change the source IP)

### Active connectivity tester

The connectivity tester runs active probe tests (only with `--probe-test`):

- MCR DNS resolution and HTTPS connectivity (standard clusters)
- Bootstrap ACR DNS and HTTPS connectivity (network-isolated clusters)
- API server DNS resolution and HTTPS connectivity (all clusters)
- HTTP proxy connectivity (proxy-configured clusters)
- Supports both VMSS and standalone VM node pools (VirtualMachines type)

### Misconfiguration analyzer

The misconfiguration analyzer performs cross-component correlation:

- Cluster provisioning failures and cluster stopped state
- Node pool provisioning failures
- Bootstrap ACR private DNS (`privatelink.azurecr.io`) VNet link validation
- Connectivity test result correlation
- DNS misconfiguration patterns (system-managed, BYO, cross-subscription)
- Permission context (prevents false positives when data is incomplete)

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
