# Azure CLI AKS Network Diagnostics Extension

[![Python](https://img.shields.io/pypi/pyversions/azure-cli.svg?maxAge=2592000)](https://pypi.python.org/pypi/azure-cli)

This is an extension for the Azure CLI to provide comprehensive network diagnostics for Azure Kubernetes Service (AKS) clusters.

## ⚠️ Preview Status

This extension is currently in **preview**. Features and commands may change in future releases. Use in production environments at your own discretion.

## Features

The `aks-net-diagnostics` extension analyzes multiple aspects of AKS cluster networking:

- **DNS Resolution**: Validates CoreDNS configuration and host DNS settings
- **Outbound Connectivity**: Tests cluster internet egress and validates firewall rules
- **Load Balancer Health Probes**: Verifies Azure Load Balancer health probe configuration
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

### Save Results to JSON

Export diagnostic results to a JSON file:

```bash
az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --json-report output.json
```

### Run Health Probe Tests

Include load balancer health probe testing:

```bash
az aks net-diagnostics --resource-group MyResourceGroup --name MyAKSCluster --probe-test
```

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
- `--probe-test`: Run load balancer health probe tests
- `--json-report`: Path to save JSON diagnostic report

## Diagnostic Categories

### 1. DNS Analyzer
- CoreDNS service status
- CoreDNS configuration
- DNS resolution tests
- Host DNS configuration

### 2. Outbound Connectivity Analyzer
- Internet egress validation
- Firewall rule checks
- Proxy configuration
- NAT gateway status

### 3. Load Balancer Analyzer
- Health probe configuration
- Backend pool membership
- Load balancing rules
- Health probe test results (with `--probe-test`)

### 4. Network Security Group (NSG) Analyzer
- NSG rules affecting AKS
- Required rule validation
- Rule priority analysis
- Security recommendations

### 5. Routes Analyzer
- Route table configuration
- Custom routes
- System routes
- Next hop validation

### 6. Private DNS Analyzer
- Private DNS zone configuration
- DNS record validation
- Zone link verification
- VNET integration

### 7. Private Link Analyzer
- Private endpoint status
- Private link service configuration
- Connection state validation
- Network interface analysis

## Understanding Results

The diagnostic tool provides results in three severity levels:

- **✅ PASS**: Configuration is correct
- **⚠️ WARNING**: Potential issue detected, may need attention
- **❌ FAIL**: Critical misconfiguration found, action required

Each finding includes:
- Category and severity
- Detailed description
- Affected resources
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
