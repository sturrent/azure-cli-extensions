# AKS Net-Diagnostics Extension - Preview Release v0.1.0b1

🎉 First preview release of the AKS Network Diagnostics extension for Azure CLI!

## ⚠️ Preview Status

This is a **preview/beta release** for testing and feedback. The extension is fully functional but may undergo changes based on community feedback before final release.

## 🔍 What's Included

Comprehensive read-only network diagnostics for AKS clusters:

- **DNS Analysis:** VNET DNS configuration and private DNS zones
- **Outbound Connectivity:** Validation of required endpoints
- **NSG Analysis:** Network Security Group rule evaluation
- **Route Tables:** UDR configuration analysis
- **API Server Access:** Configuration and connectivity checks
- **Active Probing:** Optional connectivity tests from cluster nodes

## 📦 Installation

Download the wheel file and install:

```bash
# Download the wheel file
wget https://github.com/sturrent/azure-cli-extensions/releases/download/aks-net-diagnostics-v0.1.0b1/aks_net_diagnostics-0.1.0b1-py3-none-any.whl

# Install the extension
az extension add --source aks_net_diagnostics-0.1.0b1-py3-none-any.whl
```

To remove the extension:

```bash
az extension remove --name aks-net-diagnostics
```

## 🚀 Quick Start

```bash
# Basic diagnostics
az aks net-diagnostics -g MyResourceGroup -n MyCluster

# Detailed analysis
az aks net-diagnostics -g MyResourceGroup -n MyCluster --details

# With connectivity tests
az aks net-diagnostics -g MyResourceGroup -n MyCluster --probe-test

# Save JSON report
az aks net-diagnostics -g MyResourceGroup -n MyCluster --json-report report.json
```

## 📋 Requirements

- Azure CLI 2.60.0 or later
- Appropriate Azure permissions (Reader + Network Contributor recommended)

## 🐛 Feedback

Please test and provide feedback! Report issues or suggestions at:
https://github.com/sturrent/azure-cli-extensions/issues

## 📝 Documentation

- [README](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/README.md)
- [Contributing Guide](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/CONTRIBUTING.md)

---

**Note:** This release is for preview testing before submitting to the official Azure CLI Extensions repository.
