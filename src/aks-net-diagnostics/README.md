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

- **DNS Resolution**: Validates VNET DNS configuration and private DNS zones (when configured for private clusters)
- **Outbound Connectivity**: Tests cluster internet egress and validates connectivity to required endpoints
- **Network Security Groups (NSGs)**: Checks NSG rules affecting cluster communication
- **Routes and Routing**: Analyzes route tables and custom routing configurations
- **Private DNS Zones**: Validates private DNS zone configuration for private clusters
- **Private Link**: Examines Private Link and Private Endpoint configurations

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

**Note:** The `--probe-test` option runs active connectivity tests from cluster nodes to validate DNS resolution and outbound connectivity to required endpoints. This requires Virtual Machine Contributor permissions.

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

### 1. DNS Analyzer

- VNET DNS server configuration
- Private DNS zone validation (for private clusters)
- DNS record verification
- Zone link analysis

### 2. Outbound Connectivity Analyzer

- Internet egress validation
- Connectivity to required Azure endpoints
- Proxy configuration analysis
- NAT gateway configuration

### 3. Network Security Group (NSG) Analyzer

- NSG rules affecting AKS cluster
- Required rule validation
- Rule priority analysis
- Security recommendations

### 4. Routes Analyzer

- Route table configuration
- Custom routes analysis
- System routes validation
- Next hop verification

### 5. Private DNS Analyzer

- Private DNS zone configuration for private clusters
- A-record validation
- Zone link verification
- VNET integration checks

### 6. Private Link Analyzer

- Private endpoint status
- Private link service configuration
- Connection state validation
- Network interface analysis

## Understanding Results

The diagnostic tool provides results with the following severity levels:

- **INFO**: Informational findings about your cluster configuration
- **WARNING**: Potential issues that may need attention
- **ERROR**: Configuration problems that could impact cluster functionality
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
