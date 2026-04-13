# AKS Net-Diagnostics Extension - Preview Release v0.3.0b1

Third preview release with network-isolated cluster support, HTTP proxy diagnostics, service tag detection, NAP awareness, and 12 new finding codes.

## ⚠️ Preview Status

This is a **preview/beta release** for testing and feedback. The extension is fully functional but may undergo changes based on community feedback before final release.

## 🆕 What's New in v0.3.0b1

### Network-Isolated Cluster Support (WI-1)
- Recognize outbound type `none` and `block` for network-isolated clusters
- Suppress false-positive outbound findings (no LB or NAT gateway expected)
- Validate bootstrap ACR presence — emit CRITICAL finding when missing
- Adapted NSG required rules: only DNS required for `none`/`block` (MCR, AzureCloud not needed)
- Bootstrap ACR DNS + HTTPS probe tests replace MCR probes for network-isolated clusters

### HTTP Proxy Diagnostics (WI-2)
- Detect `httpProxyConfig` and extract proxy IP/port
- VNet reachability: check if proxy IP is in the cluster VNet or reachable via peering
- NSG compliance: detect `AKS_HTTP_Proxy` rule, flag rules blocking proxy traffic
- Active probe: curl through proxy from cluster nodes (via `--probe-test`)

### Service Tags in Authorized IP Ranges (WI-3)
- Detect service tag entries (e.g., `AzureCloud`) in `authorizedIpRanges`
- Warn about single-tag limit enforced by AKS
- Detect conflict between service tags and VNet Integration (unsupported combination)

### Node Auto-Provisioning Detection (WI-4)
- Detect NAP-enabled clusters (`nodeProvisioningProfile.mode: Auto`)
- Identify Karpenter-provisioned standalone VMs via `karpenter.sh/*` and `karpenter.azure.com/*` tags
- Identify Karpenter-managed VMSS via the same tag prefixes
- Warn about subnets used by NAP nodes not covered by standard analysis
- Display VM NIC NSGs in detailed report for NAP nodes

### `defaultOutboundAccess` Awareness (WI-5)
- Read subnet-level `defaultOutboundAccess` property
- Emit per-subnet INFO findings when disabled
- Suppress from CLI output (preserved in JSON for automation)

### Additional Improvements
- **NTP rule removed**: AKS nodes use chrony with PTP from the Azure hypervisor — UDP 123 outbound is not required
- **Bootstrap ACR private DNS check**: CRITICAL validation that `privatelink.azurecr.io` has VNet link to node VNet
- **Cluster stopped state**: Detect and report stopped clusters
- **Node pool failures**: Detect node pool provisioning failures
- **VM node pool support**: Connectivity tester fallback to `virtualMachines.runCommand` for VirtualMachines-type agent pools

## 🔍 What's Included

Comprehensive read-only network diagnostics for AKS clusters:

- **DNS Analysis:** VNet DNS configuration, private DNS zones, bootstrap ACR DNS link validation
- **Outbound Connectivity:** LB, NAT GW, UDR, `none`, `block`, HTTP proxy, bootstrap ACR, `defaultOutboundAccess`
- **NSG Analysis:** Required rules (adapted for network-isolated), proxy compliance, service tags, pod CIDR rules
- **Route Tables:** UDR configuration and traffic flow impact analysis
- **API Server Access:** Authorized IP ranges, service tags, VNet Integration, private clusters
- **Active Probing:** DNS + HTTPS tests for MCR/bootstrap ACR/API server/proxy from VMSS and VM nodes
- **NAP Detection:** Karpenter VM/VMSS identification and subnet coverage warnings
- **Cross-Component Correlation:** Composite issue detection across analyzers
- **Multiple Output Formats:** JSON, YAML, TSV, and formatted table output

## 📦 Installation

Download the wheel file and install:

```bash
# Download the wheel file
wget https://github.com/sturrent/azure-cli-extensions/releases/download/aks-net-diagnostics-v0.3.0b1/aks_net_diagnostics-0.3.0b1-py3-none-any.whl

# Install the extension
az extension add --source aks_net_diagnostics-0.3.0b1-py3-none-any.whl
```

To upgrade from a previous version:

```bash
# Remove old version
az extension remove --name aks-net-diagnostics

# Install new version
az extension add --source aks_net_diagnostics-0.3.0b1-py3-none-any.whl
```

To remove the extension:

```bash
az extension remove --name aks-net-diagnostics
```

## 🚀 Usage Examples

### Basic Usage

```bash
# Default table format with formatted console report
az aks net-diagnostics -g MyResourceGroup -n MyCluster

# Detailed analysis
az aks net-diagnostics -g MyResourceGroup -n MyCluster --details

# With connectivity tests
az aks net-diagnostics -g MyResourceGroup -n MyCluster --probe-test

# Full diagnostics with JSON export
az aks net-diagnostics -g MyResourceGroup -n MyCluster --details --probe-test --json-report report.json
```

### Output Formats

```bash
# JSON output for scripting/automation
az aks net-diagnostics -g MyResourceGroup -n MyCluster -o json

# YAML output
az aks net-diagnostics -g MyResourceGroup -n MyCluster -o yaml

# TSV output for processing
az aks net-diagnostics -g MyResourceGroup -n MyCluster -o tsv

# JSON output to stdout AND save to file
az aks net-diagnostics -g MyResourceGroup -n MyCluster -o json --json-report report.json
```

## 🔧 Technical Details

**Package:** `aks_net_diagnostics-0.3.0b1-py3-none-any.whl`

**Dependencies:**
- `azure-mgmt-network~=25.0`

**Requirements:**
- Azure CLI 2.60.0 or later
- Appropriate Azure permissions (Reader recommended)
- For `--probe-test`: Virtual Machine Contributor on the MC_ resource group

**Finding Codes:** 27 total (12 new in this release)

### New Finding Codes

| Code | Severity | Description |
|------|----------|-------------|
| `OUTBOUND_TYPE_NONE` | INFO | Cluster uses outbound type `none` (network-isolated) |
| `OUTBOUND_TYPE_BLOCK` | INFO | Cluster uses outbound type `block` (network-isolated) |
| `OUTBOUND_TYPE_UNSUPPORTED` | WARNING | Unrecognized outbound type |
| `BOOTSTRAP_ACR_MISSING` | CRITICAL | Network-isolated cluster has no bootstrap ACR configured |
| `HTTP_PROXY_CONFIGURED` | INFO | HTTP proxy is configured on the cluster |
| `PROXY_NOT_REACHABLE` | WARNING | Proxy IP not reachable from the cluster VNet or peerings |
| `DEFAULT_OUTBOUND_ACCESS_DISABLED` | INFO | Subnet has `defaultOutboundAccess` disabled |
| `BOOTSTRAP_ACR_DNS_NOT_LINKED` | CRITICAL | Bootstrap ACR private DNS zone not linked to node VNet |
| `SERVICE_TAG_IN_AUTH_RANGES` | INFO | Service tag detected in authorized IP ranges |
| `SERVICE_TAG_VNET_INTEGRATION_CONFLICT` | WARNING | Service tag + VNet Integration is unsupported |
| `NAP_ENABLED` | INFO | Node Auto-Provisioning is enabled |
| `NAP_SUBNET_NOT_ANALYZED` | WARNING | NAP nodes use subnets not covered by standard analysis |

## 📝 Changes Since v0.2.0b2

See the full [CHANGELOG](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-v0.3.0/aks-net-diagnostics-integration/CHANGELOG.md) for detailed work item descriptions.

### Breaking Changes

None. All new findings are additive. Existing JSON output structure is unchanged.

## 🐛 Known Issues

- Preview release — APIs and command structure may change
- Automated tests not yet implemented (comprehensive live testing completed across 21 scenarios)
- Probe tests do not specifically target NAP/Karpenter VMs (tests run from the system pool VMSS)

## 📋 Requirements

- Azure CLI 2.60.0 or later
- Appropriate Azure permissions (Reader recommended)
- For `--probe-test`: Virtual Machine Contributor permissions on the MC_ resource group

## 🐛 Feedback

Please test and provide feedback! Report issues or suggestions at:
https://github.com/sturrent/azure-cli-extensions/issues

## 📝 Documentation

- [README](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-v0.3.0/src/aks-net-diagnostics/README.md)
- [CHANGELOG](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-v0.3.0/aks-net-diagnostics-integration/CHANGELOG.md)
- [ARCHITECTURE](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-v0.3.0/aks-net-diagnostics-integration/ARCHITECTURE.md)
- [COVERAGE MATRIX](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-v0.3.0/aks-net-diagnostics-integration/COVERAGE-MATRIX.md)

---

**Note:** This release is for preview testing before submitting to the official Azure CLI Extensions repository.
