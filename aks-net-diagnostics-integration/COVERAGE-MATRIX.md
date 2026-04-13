# AKS Net-Diagnostics Extension — Coverage Matrix

**Extension Version:** v0.3.0b1
**Last Updated:** April 13, 2026
**Status:** Preview/Beta

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Fully supported and live-tested |
| ⚠️ | Supported but not fully validated |
| ❌ | Not supported (gap) |

---

## 1. Diagnostic Findings Reference

All findings produced by the extension, grouped by analyzer module. Severity determines CLI display priority: CRITICAL findings are always actionable, WARNING findings indicate potential issues, INFO findings provide context.

### 1.1 Cluster State

| Finding Code | Severity | Trigger | Action |
|---|---|---|---|
| `CLUSTER_STOPPED` | WARNING | Cluster power state is `Stopped` | Start the cluster to enable full diagnostics |
| `CLUSTER_OPERATION_FAILURE` | CRITICAL | `provisioningState` is `Failed` | Check ARM error details in finding output |

### 1.2 Outbound Connectivity

| Finding Code | Severity | Trigger | Action |
|---|---|---|---|
| `OUTBOUND_TYPE_NONE` | INFO | Outbound type is `none` (user-managed egress) | Informational — verify egress path is configured |
| `OUTBOUND_TYPE_BLOCK` | INFO | Outbound type is `block` (AKS blocks all egress) | Informational — bootstrap ACR is mandatory |
| `OUTBOUND_TYPE_UNSUPPORTED` | INFO | Unrecognized outbound type value | Informational — extension may not fully analyze this type |
| `BOOTSTRAP_ACR_MISSING` | WARNING / CRITICAL | Network-isolated cluster has no `bootstrapProfile.containerRegistryId` | Configure bootstrap ACR. WARNING for `none`, CRITICAL for `block` |
| `DEFAULT_OUTBOUND_ACCESS_DISABLED` | INFO | Subnet has `defaultOutboundAccess: false` | Informational — suppressed from CLI output, available in JSON |
| `HTTP_PROXY_CONFIGURED` | INFO | `httpProxyConfig` detected on cluster | Informational — proxy URLs shown in details |
| `PROXY_NOT_REACHABLE` | CRITICAL | Proxy IP not within node VNet or reachable via VNet peering | Add VNet peering or route to proxy server |

### 1.3 NSG Compliance

| Finding Code | Severity | Trigger | Action |
|---|---|---|---|
| `NSG_BLOCKING_AKS_TRAFFIC` | CRITICAL | NSG deny rule blocks required AKS outbound (MCR, DNS, API server, proxy) | Remove or reprioritize the blocking rule |
| `NSG_POTENTIAL_BLOCK` | WARNING | NSG rule may block AKS traffic (ambiguous match) | Review rule priority and scope |
| `NSG_INTER_NODE_BLOCKED` | WARNING | Inbound deny rule blocks `VirtualNetwork` source | Node-to-node communication (kubelet, etc.) requires VNet inbound |
| `NSG_POD_CIDR_BLOCKED` | CRITICAL | NSG blocks Azure CNI Overlay pod CIDR traffic | Add allow rules for pod CIDR (default 10.244.0.0/16) |
| `NSG_POD_CIDR_PARTIAL` | WARNING | NSG partially blocks pod CIDR traffic | Review rules covering pod CIDR range |

### 1.4 API Server Access

| Finding Code | Severity | Trigger | Action |
|---|---|---|---|
| `API_ACCESS_RESTRICTED` | WARNING | Authorized IP ranges restrict API access | Verify client/outbound IPs are in allowed ranges |
| `UDR_CONFLICT` | WARNING / CRITICAL | UDR makes outbound IP differ from configured egress (breaks authorized IP ranges) | Align UDR routes with API server authorized ranges |
| `SERVICE_TAG_IN_AUTH_RANGES` | INFO | Service tag (e.g. `AzureCloud`) in authorized IP ranges | Informational — preview feature requiring feature flag |
| `SERVICE_TAG_VNET_INTEGRATION_CONFLICT` | WARNING | Service tags + API Server VNet Integration (incompatible) | Remove service tags or disable VNet Integration |

### 1.5 DNS & Private Cluster

| Finding Code | Severity | Trigger | Action |
|---|---|---|---|
| `PRIVATE_DNS_MISCONFIGURED` | WARNING / CRITICAL | Private DNS zone missing VNet links, or BYO DNS zone misconfigured | Add VNet link to private DNS zone |
| `DNS_RESOLUTION_FAILED` | WARNING | Probe test DNS lookup failed | Check DNS server config and NSG rules for UDP 53 |
| `BOOTSTRAP_ACR_DNS_NOT_LINKED` | CRITICAL | `privatelink.azurecr.io` zone has no VNet link to node VNet | Add VNet link — without it, ACR resolves to public IP |

### 1.6 Node Auto-Provisioning (NAP)

| Finding Code | Severity | Trigger | Action |
|---|---|---|---|
| `NAP_ENABLED` | INFO | `nodeProvisioningProfile.mode == "Auto"` | Informational — Karpenter nodes listed in details |
| `NAP_SUBNET_NOT_ANALYZED` | WARNING | NAP nodes use subnet(s) not covered by VNet analysis | Verify NSG/routing on the NAP subnet manually |

### 1.7 Permissions

| Finding Code | Severity | Trigger | Action |
|---|---|---|---|
| `PERMISSION_INSUFFICIENT_VNET` | WARNING | Cannot read VNet/subnet resources | Grant Network Reader on VNet or MC_ resource group |
| `PERMISSION_INSUFFICIENT_VMSS` | WARNING | Cannot read VMSS resources | Grant Reader on MC_ resource group |
| `PERMISSION_INSUFFICIENT_LB` | WARNING | Cannot read Load Balancer | Grant Reader on MC_ resource group |

---

## 2. Outbound Type Support

| Outbound Type | Status | Analysis | Key Checks |
|---|---|---|---|
| `loadBalancer` | ✅ | Public IP extraction from LB frontend configs and outbound rules | Missing public IPs, effective outbound IP list |
| `userDefinedRouting` | ✅ | Route table analysis, next hop detection | Blackhole routes, UDR-override of configured type, virtual appliance routing |
| `managedNATGateway` | ✅ | NAT Gateway detection in MC_ RG, public IPs and prefixes | NAT Gateway presence, IP allocation |
| `userAssignedNATGateway` | ✅ | BYO NAT Gateway detection on node subnet | User-managed NAT Gateway, IP allocation |
| `none` | ✅ | Network-isolated analysis, bootstrap ACR validation | `OUTBOUND_TYPE_NONE`, `BOOTSTRAP_ACR_MISSING` (warning), `BOOTSTRAP_ACR_DNS_NOT_LINKED` |
| `block` | ✅ | Network-isolated analysis (preview), strict bootstrap ACR requirement | `OUTBOUND_TYPE_BLOCK`, `BOOTSTRAP_ACR_MISSING` (critical), `BOOTSTRAP_ACR_DNS_NOT_LINKED` |

**Effective outbound detection:** When UDR overrides the configured type (e.g., `loadBalancer` with a 0.0.0.0/0 route to NVA), the extension detects and reports the effective path.

---

## 3. Network Plugin Support

| Network Plugin | Status | NSG Checks | Notes |
|---|---|---|---|
| Azure CNI (node subnet) | ✅ | Standard outbound + inbound rules | Default CNI mode |
| Azure CNI Overlay | ✅ | Standard + pod CIDR rules (`NSG_POD_CIDR_BLOCKED`) | Pod CIDR (default 10.244.0.0/16) traffic validated |
| Azure CNI (pod subnet) | ✅ | Standard rules, pod subnet NSG analyzed | Dual-subnet detection |
| Azure CNI Overlay + Cilium | ✅ | Same as Overlay | Live-tested with NAP clusters |
| Kubenet | ✅ | Standard rules | Bridge networking |
| BYO CNI | ❌ | Not analyzed | Pending Gap |

---

## 4. NSG Required Rules

Rules the extension checks NSGs against. Missing or blocked rules generate findings.

### Outbound Rules

| Rule | Protocol | Destination | Port | Applies To |
|---|---|---|---|---|
| `AKS_Registry_Access` | TCP | `MicrosoftContainerRegistry` | 443 | Standard clusters only (not `none`/`block`) |
| `AKS_Azure_Management` | TCP | `AzureCloud` | 443 | Standard clusters only (not `none`/`block`) |
| `AKS_DNS` | UDP | `*` | 53 | All clusters |
| `AKS_API_Server_Access` | TCP | `*` | 443 | Public clusters only (not private, not VNet Integration, not `none`/`block`) |
| `AKS_HTTP_Proxy` | TCP | `{proxy_ip}` | `{proxy_port}` | Only when `httpProxyConfig` is present |

**Note:** NTP (UDP 123) is **not** a required rule. AKS nodes use chrony with PTP from the Hyper-V host clock — no outbound NTP traffic needed.

### Inbound Rules

| Rule | Protocol | Source | Port | Applies To |
|---|---|---|---|---|
| `AKS_Inter_Node_Communication` | `*` | `VirtualNetwork` | `*` | All clusters |
| `AKS_Load_Balancer` | `*` | `AzureLoadBalancer` | `*` | All clusters |

### Network-Isolated Cluster Adjustments

For `none`/`block` outbound types, the NSG analyzer adapts:
- MCR and AzureCloud rules **removed** from required outbound (no internet access expected)
- Only DNS (UDP 53) remains required outbound
- For `block`: outbound blocking analysis **skipped** entirely (AKS deny rules are intentional)
- For `none`: only DNS blocking flagged (not TCP 443 to MCR/AzureCloud)

### Overlay Pod CIDR Checks

For Azure CNI Overlay clusters, additional NSG validation:
- Node-to-pod traffic on pod CIDR must be allowed
- Pod-to-pod traffic on pod CIDR must be allowed
- Deny rules covering pod CIDR generate `NSG_POD_CIDR_BLOCKED` (CRITICAL) or `NSG_POD_CIDR_PARTIAL` (WARNING)

---

## 5. Connectivity Probe Tests (`--probe-test`)

Active tests executed via Azure RunCommand on a node in each pool.

### Standard Clusters

| Test | Command | Success Criteria | Critical |
|---|---|---|---|
| MCR DNS Resolution | `nslookup mcr.microsoft.com` | FQDN resolves | No |
| Internet Connectivity (MCR) | `curl -v --max-time 60 --insecure https://mcr.microsoft.com/v2/` | HTTP 200/401/unauthorized | No |
| API Server DNS | `nslookup {fqdn}` | FQDN resolves; private IP for private clusters | Yes |
| API Server HTTPS | `curl -v -k --max-time 15 https://{fqdn}:443` | HTTP 200/401/403 | Yes |

### Network-Isolated Clusters (`none`/`block`)

| Test | Command | Success Criteria | Critical |
|---|---|---|---|
| Bootstrap ACR DNS | `nslookup {acr}.azurecr.io` | Resolves to private IP | Yes |
| Bootstrap ACR HTTPS | `curl -v --max-time 60 --insecure https://{acr}.azurecr.io/v2/` | HTTP 200/401/unauthorized | Yes |
| API Server DNS | `nslookup {fqdn}` | FQDN resolves | Yes |
| API Server HTTPS | `curl -v -k --max-time 15 https://{fqdn}:443` | HTTP 200/401/403 | Yes |

### HTTP Proxy Clusters

| Test | Command | Success Criteria | Critical |
|---|---|---|---|
| HTTP Proxy Connectivity | `curl -v --max-time 15 --proxy-insecure -x {proxy_url} https://mcr.microsoft.com/v2/` | HTTP 200/401/407 | Yes |
| *(plus standard or isolated tests above)* | | | |

**Execution details:**
- Runs on **one node per pool** (first ready VMSS instance or VM)
- Supports both VMSS and standalone VM node pools
- Skipped when cluster is stopped, failed, or permissions insufficient
- Test dependencies: connectivity tests skip if DNS resolution fails first

---

## 6. Cluster Configuration Support

| Configuration | Status | What's Checked |
|---|---|---|
| Public Cluster | ✅ | Outbound IPs, NSG rules, API server access |
| Private Cluster (system-managed DNS) | ✅ | `privatelink.{region}.azmk8s.io` zone, VNet links |
| Private Cluster (BYO Private DNS Zone) | ✅ | Cross-subscription VNet link validation |
| Private Cluster (API VNet Integration) | ✅ | Delegated subnet NSG, VNet Integration-specific rules |
| Authorized IP Ranges (CIDRs) | ✅ | Client IP auth, outbound IP auth, overly permissive ranges, UDR conflicts |
| Authorized IP Ranges (Service Tags) | ✅ | Service tag detection, multiple-tag warning, VNet Integration conflict |
| HTTP Proxy | ✅ | Proxy VNet reachability, NSG compliance, probe through proxy |
| Node Auto-Provisioning (NAP) | ✅ | Karpenter VM detection (standalone VMs, not VMSS), subnet coverage |
| Multiple Node Pools | ✅ | Per-pool analysis, summary + detailed views |
| Mixed VMSS + VM Pools | ✅ | Both types analyzed, probes run on both |

---

## 7. VNet Topology Support

| Topology | Status | What's Checked |
|---|---|---|
| AKS-Managed VNet | ✅ | Subnet CIDRs, NSGs, route tables, `defaultOutboundAccess` |
| BYO VNet (same subscription) | ✅ | Same as managed + BYO-specific checks |
| BYO VNet (cross-subscription) | ⚠️ | Code supports, not live-tested |
| Hub-Spoke with UDR | ✅ | Route table analysis, NVA next-hop detection, blackhole routes |
| VNet Peering | ✅ | Peering detection, peer VNet address prefix resolution (used for proxy reachability) |

---

## 8. Node Infrastructure Support

| Infrastructure | Status | Probe Tests | NSG Analysis | Notes |
|---|---|---|---|---|
| VMSS (standard) | ✅ | ✅ RunCommand on VMSS | ✅ NIC + subnet NSGs | Primary node type |
| Virtual Machines node pools | ✅ | ✅ RunCommand on VM | ✅ NIC + subnet NSGs | VirtualMachines type pools |
| Karpenter VMs (NAP) | ✅ | ✅ RunCommand on VM | ✅ NIC + subnet NSGs | Detected by `karpenter.sh_*` / `karpenter.azure.com_*` tags |
| Virtual Nodes (ACI) | ❌ | ❌ | ❌ | No ACI support (Pending Gap) |

---

## 9. DNS Analysis

| Check | Status | Details |
|---|---|---|
| Azure Default DNS (168.63.129.16) | ✅ | Detection |
| Custom DNS Servers on VNet | ✅ | Reachability warnings |
| Private DNS Zone (system-managed) | ✅ | Zone detection, VNet link validation |
| Private DNS Zone (BYO, cross-subscription) | ✅ | Cross-subscription VNet link check |
| Bootstrap ACR Private DNS (`privatelink.azurecr.io`) | ✅ | VNet link validation — `BOOTSTRAP_ACR_DNS_NOT_LINKED` if missing |
| Custom DNS + Private DNS Zones | ✅ | Hub VNet DNS zone link warnings |
| AKS LocalDNS (Preview) | ⚠️ | Not tested — may affect probe test DNS resolution |

---

## 10. Permission Handling

| Scenario | Behavior |
|---|---|
| Full permissions | Complete analysis across all phases |
| Missing VNet/Subnet read | Skips VNet analysis, emits `PERMISSION_INSUFFICIENT_VNET` |
| Missing VMSS/VM read | Skips NIC-level NSG and probe tests, emits `PERMISSION_INSUFFICIENT_VMSS` |
| Missing LoadBalancer read | Skips LB outbound IP extraction, emits `PERMISSION_INSUFFICIENT_LB` |
| Missing RunCommand execute | Skips probe tests, reports permission issue |
| All permissions missing | Reports all permission findings, delivers what analysis it can |

---

## 11. Output Formats

| Format | Flag | Notes |
|---|---|---|
| Console summary | *(default)* | Findings grouped by severity, probe results, cluster overview |
| Console detailed | `--details` | Expanded NSG rules, route tables, node pool details |
| JSON report | `--json-report` | Machine-readable full diagnostic output |
| Table | `-o table` | Azure CLI standard |
| JSON | `-o json` | Azure CLI standard |
| YAML | `-o yaml` | Azure CLI standard |
| TSV | `-o tsv` | Azure CLI standard |

**CLI suppression:** `DEFAULT_OUTBOUND_ACCESS_DISABLED` findings are hidden from console output (both summary and `--details`) to reduce noise. They remain in JSON output for programmatic consumers.

---

## 12. Remaining Gaps

| Gap | Impact | Notes |
|---|---|---|
| CIDR overlap detection | Medium | Detect pod/service CIDR conflicts with VNet subnets. TODO placeholder in `misconfiguration_analyzer.py`. High value for BYO VNet + NAP. |
| Dual-stack / IPv6 | Medium | Cross-cutting change across all analyzers |
| Virtual Nodes (ACI) | Low | No RunCommand support, different networking model |
| AKS LocalDNS (Preview) | Low | May affect DNS probe results on nodes using 169.254.10.10/11 |
| Custom endpoint testing | Low | Requires new CLI parameter design |
| BYO CNI | Low | Niche adoption, unknown NSG requirements |

---

## 13. Live-Tested Scenarios

All scenarios below were tested against real AKS clusters during v0.3.0 development.

| # | Scenario | Key Validations |
|---|---|---|
| 1 | Public cluster + Load Balancer | Outbound IPs, NSG compliance, API access, probes 4/4 |
| 2 | Private cluster + system-managed DNS | Private DNS zone, VNet links, probe DNS resolution |
| 3 | Private cluster + BYO DNS (cross-sub) | Cross-subscription VNet link validation |
| 4 | Private cluster + VNet Integration | Delegated subnet NSG, VNet Integration rules |
| 5 | UDR + Firewall (hub-spoke) | Route table, NVA next hop, UDR override detection |
| 6 | NAT Gateway (managed) | NAT Gateway in MC_ RG, public IP extraction |
| 7 | NAT Gateway (user-assigned) | BYO NAT Gateway on subnet |
| 8 | Network-isolated (`block`) + managed VNet | `OUTBOUND_TYPE_BLOCK`, bootstrap ACR checks, ACR probe 4/4 |
| 9 | Network-isolated (`none`) + BYO VNet | `OUTBOUND_TYPE_NONE`, bootstrap ACR, private DNS VNet link, ACR probe 4/4 |
| 10 | Network-isolated + missing ACR DNS link | `BOOTSTRAP_ACR_DNS_NOT_LINKED` CRITICAL detected; restored → clean |
| 11 | HTTP proxy (working) | `HTTP_PROXY_CONFIGURED` INFO, proxy probe PASSED, 5/5 |
| 12 | HTTP proxy + NSG deny on proxy IP:port | `NSG_BLOCKING_AKS_TRAFFIC` CRITICAL |
| 13 | HTTP proxy + broken VNet peering | `PROXY_NOT_REACHABLE` CRITICAL, proxy probe FAILED |
| 14 | Service tags in authorized IP ranges (single) | `SERVICE_TAG_IN_AUTH_RANGES` INFO |
| 15 | Service tags (multiple) | Multiple-tag WARNING |
| 16 | NAP + managed VNet | `NAP_ENABLED` INFO, probes 4/4 |
| 17 | NAP + BYO VNet + Karpenter VM | Karpenter VM detected, NIC NSG mapped, `NAP_ENABLED` with node list |
| 18 | NAP + BYO VNet + NSG breakage on NAP subnet | 3 blocking findings: `NSG_BLOCKING_AKS_TRAFFIC`, `NSG_INTER_NODE_BLOCKED`, `NSG_POD_CIDR_BLOCKED` |
| 19 | Azure CNI Overlay NSG | Pod CIDR rules validated |
| 20 | VM node pools | RunCommand on VMs, NIC NSG analysis |
| 21 | Limited permissions | Graceful degradation with permission findings |

---

## 14. Extension Release History

### v0.3.0b1 (April 2026)
- ✅ Network-isolated cluster support (outbound `none`/`block`)
- ✅ Bootstrap ACR validation and private DNS VNet link check
- ✅ HTTP proxy diagnostics (VNet reachability, NSG compliance, proxy probe)
- ✅ Service tag detection in authorized IP ranges
- ✅ Node Auto-Provisioning (NAP) detection with Karpenter VM support
- ✅ `defaultOutboundAccess` subnet awareness
- ✅ NSG adjustments for network-isolated clusters
- ✅ Bootstrap ACR-specific probe tests for isolated clusters
- ✅ Removed incorrect NTP required outbound rule

### v0.2.0b2 (March 2026)
- ✅ SDK dependency optimization

### v0.2.0b1 (November 2025)
- ✅ Full Azure CLI output format support (json, yaml, tsv, table)
- ✅ Azure CLI 2.79.0 compatibility

### v0.1.0b1 (November 2025)
- ✅ Initial preview release
- ✅ Azure CNI Overlay NSG validation
- ✅ VM node pools support
- ✅ API Server VNet Integration
- ✅ BYO Private DNS Zone (cross-subscription)
