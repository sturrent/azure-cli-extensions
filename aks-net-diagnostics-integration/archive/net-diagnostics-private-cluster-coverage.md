# AKS Net-Diagnostics: Private Cluster Checks Coverage

This document details what the `aks-net-diagnostics` extension currently implements for private cluster validation, mapped to private cluster suggested requirements.

**Repository:** [sturrent/azure-cli-extensions](https://github.com/sturrent/azure-cli-extensions/tree/aks-net-diagnostics-extension)  
**Extension Path:** `src/aks-net-diagnostics/azext_aks_net_diagnostics/`

---

## What AKS Net-Diagnostics Currently Does (Private Cluster Checks)

| PRD Requirement | Net-Diagnostics Status | Implementation Details | Source Code |
|----------------|----------------------|------------------------|-------------|
| **Missing VNet Link to Private DNS Zone** | ✅ **Fully Implemented** | Validates VNet links for both system-managed and BYO DNS zones, including **cross-subscription support** | [`misconfiguration_analyzer.py` → `_check_private_dns_vnet_links()`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/misconfiguration_analyzer.py#L620-L750) |
| **BYO Private DNS Zone Validation** | ✅ **Fully Implemented** | Handles full resource IDs, creates cross-subscription `PrivateDnsManagementClient` when needed | [`misconfiguration_analyzer.py` → `_get_privatedns_client_for_zone()`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/misconfiguration_analyzer.py#L42-L85) |
| **System-managed DNS Zone Validation** | ✅ **Fully Implemented** | Finds zones in MC_ resource group and validates links | [`misconfiguration_analyzer.py` → `_check_system_private_dns_issues()`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/misconfiguration_analyzer.py#L358-L430) |
| **Custom DNS Server Detection** | ✅ **Fully Implemented** | Detects VNet custom DNS servers and warns about compatibility | [`dns_analyzer.py` → `_analyze_vnet_dns_servers()`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/dns_analyzer.py#L200-L280) |
| **DNS Server Host VNet Link Check** | ✅ **Fully Implemented** | Validates that hub VNets hosting DNS servers are linked to private DNS zone | [`misconfiguration_analyzer.py` → `_check_dns_server_vnet_links()`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/misconfiguration_analyzer.py#L432-L500) |
| **Private vs VNet Integration Detection** | ✅ **Fully Implemented** | Properly distinguishes `private_endpoint`, `vnet_integration_public`, `vnet_integration_private` modes | [`api_server_analyzer.py` → `_determine_access_mode()`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/api_server_analyzer.py#L125-L145) |
| **API Server VNet Integration Detection** | ✅ **Fully Implemented** | Checks `enable_vnet_integration` flag and additional properties | [`api_server_analyzer.py` → `_is_vnet_integration_enabled()`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/api_server_analyzer.py#L97-L120) |
| **NSG Blocking API Server** | ✅ **Fully Implemented** | Validates required inbound/outbound rules, inter-node communication | [`nsg_analyzer.py` → `analyze()`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/nsg_analyzer.py) |
| **UDR/NVA Analysis** | ✅ **Fully Implemented** | Detects default routes through virtual appliances, warns about API server connectivity impact | [`route_table_analyzer.py` → `analyze()`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/route_table_analyzer.py) + [`outbound_analyzer.py`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/outbound_analyzer.py) |
| **Active Connectivity Testing (DNS + API)** | ✅ **Implemented** | Tests MCR and API server DNS resolution + HTTPS from VMSS or VM nodes (requires running cluster) | [`connectivity_tester.py` → `test_connectivity()`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/connectivity_tester.py#L70-L150) |
| **Identity/RBAC Permissions** | ⚠️ **Partial** | Detects permission failures gracefully but doesn't **validate** UAMI permissions on DNS zones | [`misconfiguration_analyzer.py`](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/misconfiguration_analyzer.py) - permission error handling throughout |
| **DNS Zone Name Format Validation** | ❌ **Not Implemented** | Doesn't validate zone name matches `privatelink.<region>.azmk8s.io` format | N/A |
| **Pre-Flight Validation (before cluster exists)** | ❌ **Not Implemented** | Tool only works on **existing clusters** | N/A |

---

## Key Implementation Files

| File | Description | GitHub Link |
|------|-------------|-------------|
| `misconfiguration_analyzer.py` | Core private cluster DNS validation logic | [View Source](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/misconfiguration_analyzer.py) |
| `dns_analyzer.py` | DNS configuration analysis, VNet DNS servers | [View Source](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/dns_analyzer.py) |
| `api_server_analyzer.py` | API server access mode detection, VNet integration | [View Source](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/api_server_analyzer.py) |
| `nsg_analyzer.py` | NSG rule analysis for AKS requirements | [View Source](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/nsg_analyzer.py) |
| `route_table_analyzer.py` | UDR and route table analysis | [View Source](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/route_table_analyzer.py) |
| `outbound_analyzer.py` | Outbound connectivity analysis | [View Source](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/outbound_analyzer.py) |
| `connectivity_tester.py` | Active probe testing from nodes | [View Source](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/connectivity_tester.py) |
| `orchestrator.py` | Main orchestration of all analyzers | [View Source](https://github.com/sturrent/azure-cli-extensions/blob/aks-net-diagnostics-extension/src/aks-net-diagnostics/azext_aks_net_diagnostics/orchestrator.py) |

---

## Key Functions for Private Cluster Validation

### 1. VNet Link Validation (BYO Private DNS Zone)

```
misconfiguration_analyzer.py:
├── _check_private_dns_vnet_links()     # Main validation entry point
├── _get_privatedns_client_for_zone()   # Cross-subscription client creation
├── _get_cluster_vnet_ids()             # Get all VNets used by cluster
└── _find_private_dns_zone_rg()         # Locate DNS zone resource group
```

### 2. System-Managed DNS Zone Validation

```
misconfiguration_analyzer.py:
├── _check_system_private_dns_issues()  # Find zones in MC_ resource group
└── _check_dns_server_vnet_links()      # Validate custom DNS server VNet links
```

### 3. API Server Access Analysis

```
api_server_analyzer.py:
├── analyze()                           # Main analysis entry point
├── _is_vnet_integration_enabled()      # Detect VNet Integration mode
├── _determine_access_mode()            # Classify access model
└── _analyze_authorized_ip_ranges()     # IP range security analysis
```

### 4. DNS Configuration Analysis

```
dns_analyzer.py:
├── analyze()                           # Main analysis entry point
├── _analyze_private_dns_zone()         # Private DNS zone configuration
├── _analyze_vnet_dns_servers()         # Custom DNS server detection
└── _is_vnet_integration_enabled()      # VNet Integration check
```

---

## Gaps Requiring Implementation

- DNS Zone Name Format Validation (`privatelink.<region>.azmk8s.io`)
- UAMI Permission Validation on DNS Zone
- Pre-Flight Validation Mode (tool only works on existing clusters)

---

## Related Documentation

- [Coverage Matrix](./COVERAGE-MATRIX.md)
- [Extension README](../src/aks-net-diagnostics/README.md)
