# Azure CLI AKS Network Diagnostics Extension

[![Python](https://img.shields.io/pypi/pyversions/azure-cli.svg?maxAge=2592000)](https://pypi.python.org/pypi/azure-cli)

This is an extension for the Azure CLI to provide comprehensive network diagnostics for Azure Kubernetes Service (AKS) clusters.

## ⚠️ Preview Status

This extension is currently in **preview**. Features and commands may change in future releases. Use in production environments at your own discretion.

## 🔍 Read-Only Analysis

**This tool performs read-only analysis only** - it will not modify any resources or configurations in your AKS cluster or Azure environment. All diagnostics are performed by analyzing existing configurations and resources.

## 🔐 Permission Requirements

The diagnostic tool runs using **your Azure CLI credentials** and requires specific permissions to access cluster and network resources. Depending on your role assignments and the cluster's configuration:

- Some diagnostic checks may be skipped if you lack sufficient permissions
- The tool will clearly indicate which checks were skipped and what permissions are needed
- For complete diagnostics, ensure you have read permissions on the cluster, network, compute, and private DNS resources

**Recommended minimum permissions:**
- `Microsoft.ContainerService/managedClusters/read`
- `Microsoft.Network/*/read`
- `Microsoft.Compute/*/read`
- `Microsoft.Network/privateDnsZones/read`

## Features

The `aks-net-diagnostics` extension analyzes multiple aspects of AKS cluster networking:

- **Outbound Connectivity**: Analyzes outbound type configuration (Load Balancer, NAT Gateway, UDR, `none`, `block`), extracts effective outbound IPs, and validates bootstrap ACR for network-isolated clusters
- **Network Security Groups (NSGs)**: Checks NSG rules on subnets and NICs against required AKS rules, validates inter-node communication, and detects pod CIDR blocking for Azure CNI Overlay
- **DNS & Private DNS**: Validates VNET DNS configuration, private DNS zones for private clusters, and `privatelink.azurecr.io` VNet links for bootstrap ACR
- **Routes and Routing**: Analyzes route tables, detects blackhole routes and UDR overrides of configured outbound type
- **API Server Access**: Validates authorized IP ranges, detects UDR conflicts, and checks service tag compatibility with VNet Integration
- **HTTP Proxy**: Detects proxy configuration, validates proxy reachability from node VNet, checks NSG compliance for proxy traffic, and runs probe tests through the proxy
- **Node Auto-Provisioning (NAP)**: Detects NAP-enabled clusters, identifies Karpenter-provisioned VMs, and checks subnet coverage
- **Active Probe Tests**: Runs DNS and HTTPS connectivity tests from cluster nodes (VMSS and VM) via Azure RunCommand

## Installation

### Prerequisites

- Azure CLI version 2.60.0 or later
- Python 3.10 or later

### Install the Extension

```bash
az extension add --name aks-net-diagnostics
```

### Verify Installation

```bash
az extension list --output table
```

## Usage

### Basic Diagnostics

Run basic network diagnostics on an AKS cluster:

```bash
az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster
```

### Detailed Output

Get verbose diagnostic information:

```bash
az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --details
```

### Output Formats

The extension supports all standard Azure CLI output formats:

```bash
# Table format (default) - Human-readable console report with findings
az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster

# JSON format - Complete diagnostic data in JSON
az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster -o json

# YAML format - Complete diagnostic data in YAML
az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster -o yaml

# TSV format - Tab-separated values for scripting
az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster -o tsv
```

**Note:** When using `-o json`, `-o yaml`, or `-o tsv`, the console report is suppressed and only the structured data is returned. The table format (default) shows the formatted console report with diagnostic findings.

### Save Results to JSON File

Export diagnostic results to a JSON file while still showing the console report:

```bash
az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --json-report output.json
```

**Tip:** You can combine `--json-report` with any output format. For example, use `-o json --json-report output.json` to both return JSON to stdout and save to a file.

### Run Health Probe Tests

Include active DNS resolution and outbound connectivity tests from cluster nodes:

```bash
az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --probe-test
```

**Note:** The `--probe-test` option runs active connectivity tests from cluster nodes (VMSS and VM node pools) to validate DNS resolution and outbound connectivity to required endpoints. This requires Virtual Machine Contributor permissions on the cluster's node resource group.

### Full Diagnostics

Run complete diagnostics with all options:

```bash
az aks net-diagnostics \
    --resource-group MyResourceGroup \
    --name MyAKSCluster \
    --details \
    --probe-test \
    --json-report diagnostics-report.json
```

## Command Reference

### `az aks net-diagnostics`

Runs comprehensive network diagnostics on an AKS cluster.

**Required Arguments:**

- `--resource-group -g`: Name of resource group containing the AKS cluster
- `--name -n`: Name of the AKS cluster

**Optional Arguments:**

- `--details`: Show detailed diagnostic information
- `--probe-test`: Run active DNS resolution and outbound connectivity tests from cluster nodes (requires Virtual Machine Contributor permissions)
- `--json-report`: Path to save JSON diagnostic report

## Diagnostic Categories

### Outbound Connectivity Analyzer

- Outbound type detection and analysis: `loadBalancer`, `managedNATGateway`, `userAssignedNATGateway`, `userDefinedRouting`, `none`, `block`
- Public IP extraction from Load Balancer and NAT Gateway
- Effective outbound path detection (UDR override of configured type)
- Bootstrap ACR validation for network-isolated clusters (`none`/`block`)
- HTTP proxy configuration detection, VNet reachability, and NSG compliance
- `defaultOutboundAccess` subnet awareness

### NSG Analyzer

- Required outbound rules: MCR, AzureCloud, DNS, API server, HTTP proxy
- Required inbound rules: inter-node communication, Load Balancer health probes
- Azure CNI Overlay pod CIDR traffic validation
- Blocking rule detection with priority-based analysis
- Adapted rule sets for network-isolated clusters (DNS only)

### DNS Analyzer

- VNET DNS server configuration (Azure default vs custom)
- Private DNS zone validation and VNet link checks
- Bootstrap ACR private DNS (`privatelink.azurecr.io`) VNet link validation
- Cross-subscription BYO private DNS zone support

### API Server Access Analyzer

- Authorized IP ranges validation (CIDR and service tags)
- Client IP and outbound IP authorization checks
- UDR conflict detection (effective outbound IP vs authorized ranges)
- Service tag compatibility with API Server VNet Integration

### Routes Analyzer

- Route table analysis on node subnets
- Default route (0.0.0.0/0) next-hop detection
- Blackhole route detection
- Virtual appliance (NVA/firewall) routing

### Connectivity Tester (`--probe-test`)

- MCR DNS resolution and HTTPS connectivity (standard clusters)
- Bootstrap ACR DNS and HTTPS connectivity (network-isolated clusters)
- API server DNS resolution and HTTPS connectivity (all clusters)
- HTTP proxy connectivity test (proxy clusters)
- Runs on both VMSS and VM node pools via Azure RunCommand

### Misconfiguration Analyzer

- Cross-component correlation of findings from all analyzers
- Cluster state checks (stopped, failed provisioning)
- Node pool provisioning state validation
- NAP detection and Karpenter VM subnet coverage analysis

## Understanding Results

The diagnostic tool provides results with the following severity levels:

- **INFO**: Informational findings about your cluster configuration
- **WARNING**: Potential issues that may need attention
- **CRITICAL**: Severe misconfigurations requiring immediate action

Each finding includes:

- Category and severity level
- Detailed description of the issue
- Affected resources and their configurations
- Recommended remediation steps

## Troubleshooting

### Authentication Issues

Ensure you're logged in to Azure CLI:

```bash
az login
az account show
```

### Permission Issues

The diagnostic tool requires the following permissions:

- `Microsoft.ContainerService/managedClusters/read`
- `Microsoft.Network/*/read`
- `Microsoft.Compute/*/read`
- `Microsoft.Network/privateDnsZones/read`

If you lack certain permissions, the tool will skip related checks and indicate what permissions are needed in the output.

### Extension Not Found

If the extension is not found after installation:

```bash
az extension list
az extension add --name aks-net-diagnostics --upgrade
```

## Development

To contribute to this extension, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Feedback and Issues

For bugs, feature requests, or questions:
- Open an issue on the [Azure CLI Extensions GitHub repository](https://github.com/Azure/azure-cli-extensions/issues)
- Tag issues with `aks-net-diagnostics`

## Related Documentation

- [AKS Networking Concepts](https://docs.microsoft.com/azure/aks/concepts-network)
- [AKS Network Best Practices](https://docs.microsoft.com/azure/aks/operator-best-practices-network)
- [Troubleshoot AKS Network Issues](https://docs.microsoft.com/azure/aks/troubleshooting)

## License

This project is licensed under the MIT License. See [LICENSE](../../LICENSE) for details.
