# Changelog - AKS Net-Diagnostics Extension

## v0.3.0b1 - April 2026

### WI-1: Outbound Type `none` and `block` Support

Added recognition of network-isolated clusters using outbound type `none` or `block`.

- Detect `none` and `block` outbound types from the cluster network profile
- Suppress false-positive outbound findings (no load balancer or NAT gateway expected)
- Validate bootstrap ACR presence for network-isolated clusters
- Emit `OUTBOUND_TYPE_NONE` / `OUTBOUND_TYPE_BLOCK` INFO findings
- Emit `BOOTSTRAP_ACR_MISSING` CRITICAL finding when bootstrap ACR is not configured

**Files modified:** `outbound_analyzer.py`, `models.py`

### WI-2: HTTP Proxy Configuration Awareness

Full proxy lifecycle diagnostics across detection, NSG compliance, and active probe testing.

**Phase 1 — Detection & Extraction:**
- Detect `httpProxyConfig` on the cluster and extract proxy IP/port
- Report proxy configuration as `HTTP_PROXY_CONFIGURED` INFO finding

**Phase 2 — Actionable Proxy Diagnostics:**
- VNet reachability: check if proxy IP is in the cluster VNet or reachable via peering
- NSG compliance: detect `AKS_HTTP_Proxy` rule presence, flag rules blocking proxy traffic
- Connectivity probe: curl through proxy from cluster nodes (via `--probe-test`)
- Emit `PROXY_NOT_REACHABLE` WARNING when proxy IP is not in any reachable VNet/peering

**Files modified:** `outbound_analyzer.py`, `nsg_analyzer.py`, `connectivity_tester.py`, `models.py`

### WI-3: Service Tags in Authorized IP Ranges

Detect service tag entries in `authorizedIpRanges` to avoid CIDR parsing errors and surface operational constraints.

- Identify service tag names (e.g., `AzureCloud`) mixed with CIDR entries
- Warn about single-tag limit enforced by AKS
- Detect conflict between service tags and VNet Integration (unsupported combination)
- Emit `SERVICE_TAG_IN_AUTH_RANGES` INFO and `SERVICE_TAG_VNET_INTEGRATION_CONFLICT` WARNING findings

**Files modified:** `api_server_analyzer.py`, `misconfiguration_analyzer.py`, `models.py`

### WI-4: Node Auto-Provisioning (NAP) Detection

Detect NAP-enabled clusters and identify Karpenter-managed infrastructure.

- Detect `nodeProvisioningProfile.mode: Auto` on the cluster
- Identify Karpenter-provisioned standalone VMs via `karpenter.sh/*` and `karpenter.azure.com/*` tags
- Identify Karpenter-managed VMSS via the same tag prefixes
- Warn about subnets used by NAP nodes that weren't covered by the standard NSG/DNS analysis
- Display VM NIC NSGs in the detailed report for NAP nodes
- Emit `NAP_ENABLED` INFO and `NAP_SUBNET_NOT_ANALYZED` WARNING findings

**Files modified:** `cluster_data_collector.py`, `orchestrator.py`, `report_generator.py`, `models.py`

### WI-5: `defaultOutboundAccess` Retirement Awareness

Surface subnet-level `defaultOutboundAccess` status.

- Read `default_outbound_access` property from each cluster subnet
- Emit per-subnet `DEFAULT_OUTBOUND_ACCESS_DISABLED` INFO findings
- Suppress these findings from CLI console output (noisy for multi-subnet clusters)
- Preserve findings in JSON report for automation consumers

**Files modified:** `cluster_data_collector.py`, `outbound_analyzer.py`, `orchestrator.py`, `report_generator.py`, `models.py`

### Additional Enhancements

**NSG analyzer — network isolation adaptation:**
- Adapted required outbound rules for `none`/`block` clusters (only DNS required; MCR, AzureCloud not needed)
- Skip outbound blocking analysis for `block` type (blocking is expected)
- Removed NTP (UDP 123) from required outbound rules — AKS nodes use chrony with PTP from the Azure hypervisor and do not require outbound NTP

**Connectivity tester — bootstrap ACR and proxy probes:**
- Bootstrap ACR DNS + HTTPS probe tests for `none`/`block` clusters (replaces MCR probes)
- HTTP proxy connectivity probe for proxy-configured clusters
- VM node pool support: fallback to `virtualMachines.runCommand` for clusters with no VMSS (VirtualMachines-type agent pools)

**Misconfiguration analyzer — bootstrap ACR DNS link:**
- CRITICAL check: validate that `privatelink.azurecr.io` private DNS zone has a VNet link to the node VNet
- Cross-subscription ACR support (bootstrap ACR in a different subscription)
- Added cluster stopped state detection and node pool provisioning failure detection

**Report generator — VM NIC NSG display:**
- Show NIC-level NSGs for standalone VMs (NAP/Karpenter nodes, VirtualMachines-type pools) in detailed output

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

### Breaking Changes

None. All new findings are additive. Existing JSON output structure is unchanged.
