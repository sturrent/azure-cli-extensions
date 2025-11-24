# AKS Net-Diagnostics Extension - Preview Release v0.2.0b1

🎉 Second preview release with output format enhancements and Azure CLI 2.79.0 compatibility!

## ⚠️ Preview Status

This is a **preview/beta release** for testing and feedback. The extension is fully functional but may undergo changes based on community feedback before final release.

## 🆕 What's New in v0.2.0b1

### Output Format Support
- **Full Azure CLI output format support**: `-o json`, `-o yaml`, `-o tsv`, `-o table` (default)
- Automatic console report suppression when using structured output formats (json/yaml/tsv)
- Optimized JSON generation for better performance (single generation, reused for file and output)

### Improvements
- **Azure CLI 2.79.0 Compatibility**: Updated all Azure SDK dependencies
- **Improved JSON Structure**: Better key ordering ensures findings always appear at end for easier viewing
- **Cleaner Output**: Removed unused `failure_analysis` field
- **Enhanced Documentation**: Added comprehensive output format usage examples

## 🔍 What's Included

Comprehensive read-only network diagnostics for AKS clusters:

- **DNS Analysis:** VNET DNS configuration and private DNS zones
- **Outbound Connectivity:** Validation of required endpoints
- **NSG Analysis:** Network Security Group rule evaluation
- **Route Tables:** UDR configuration analysis
- **API Server Access:** Configuration and connectivity checks
- **Active Probing:** Optional connectivity tests from cluster nodes
- **Multiple Output Formats:** JSON, YAML, TSV, and formatted table output

## 📦 Installation

Download the wheel file and install:

```bash
# Download the wheel file
wget https://github.com/sturrent/azure-cli-extensions/releases/download/aks-net-diagnostics-v0.2.0b1/aks_net_diagnostics-0.2.0b1-py3-none-any.whl

# Install the extension
az extension add --source aks_net_diagnostics-0.2.0b1-py3-none-any.whl
```

To upgrade from v0.1.0b1:

```bash
# Remove old version
az extension remove --name aks-net-diagnostics

# Install new version
az extension add --source aks_net_diagnostics-0.2.0b1-py3-none-any.whl
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
```

### Output Formats (New!)

```bash
# JSON output for scripting/automation
az aks net-diagnostics -g MyResourceGroup -n MyCluster -o json

# YAML output
az aks net-diagnostics -g MyResourceGroup -n MyCluster -o yaml

# TSV output for processing
az aks net-diagnostics -g MyResourceGroup -n MyCluster -o tsv

# Save to file while showing console report
az aks net-diagnostics -g MyResourceGroup -n MyCluster --json-report report.json

# JSON output to stdout AND save to file
az aks net-diagnostics -g MyResourceGroup -n MyCluster -o json --json-report report.json
```

## 🔧 Technical Details

**Package:** `aks_net_diagnostics-0.2.0b1-py3-none-any.whl` (89KB)

**Dependencies (Updated for Azure CLI 2.79.0):**
- `azure-mgmt-network~=25.0` (previously 30.0)
- `azure-mgmt-compute~=34.1` (previously 33.0)
- `azure-mgmt-containerservice~=40.1` (previously 33.0)
- `azure-mgmt-privatedns~=1.0` (previously 1.1)

**Requirements:**
- Azure CLI 2.60.0 or later (tested with 2.79.0)
- Appropriate Azure permissions (Reader + Network Contributor recommended)

## 📝 Changes Since v0.1.0b1

### Features
- Added support for all Azure CLI output formats (json, yaml, tsv, table)
- Console report automatically suppressed for non-table output formats
- Optimized JSON generation (generated once, reused for file export and command output)

### Improvements
- Updated Azure SDK dependencies to align with Azure CLI 2.79.0
- Improved JSON structure with better alphabetical key ordering
- Removed unused `failure_analysis` field from JSON output
- Enhanced README with comprehensive output format documentation

### Bug Fixes
- Fixed `ModuleNotFoundError: azure.mgmt.compute.v2024_11_01` compatibility issue
- Resolved Azure SDK version conflicts with Azure CLI 2.79.0

## 🐛 Known Issues

- Preview release - APIs and command structure may change
- Automated tests not yet implemented (comprehensive manual testing completed)

## 📋 Requirements

- Azure CLI 2.60.0 or later (recommended: 2.79.0)
- Appropriate Azure permissions (Reader + Network Contributor recommended)
- For `--probe-test`: Virtual Machine Contributor permissions

## 🐛 Feedback

Please test and provide feedback! Report issues or suggestions at:
https://github.com/sturrent/azure-cli-extensions/issues

## 📝 Documentation

- [README](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/README.md)
- [CHANGELOG](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/aks-net-diagnostics-integration/CHANGELOG.md)
- [HISTORY](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/HISTORY.rst)
- [Contributing Guide](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/CONTRIBUTING.md)

---

**Note:** This release is for preview testing before submitting to the official Azure CLI Extensions repository.
