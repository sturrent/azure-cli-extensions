# AKS Net-Diagnostics v0.3.0 Implementation Plan

**Branch:** `aks-net-diagnostics-v0.3.0`
**Base:** `aks-net-diagnostics-extension` (v0.2.0b2)
**Reference:** [net-diagnostics-functionality-and-gaps.md](net-diagnostics-functionality-and-gaps.md)

---

## Progress Summary

| Work Item | Status | Commits | Live Tested |
|-----------|--------|---------|-------------|
| WI-5: defaultOutboundAccess | **Done** | `795efbd`, `14c4ed4` | Managed + BYO VNet |
| WI-1: Outbound none/block | **Done** | `876816c`, `dc30e91` | Managed (block) + BYO (none) |
| WI-2: HTTP proxy awareness | **Done** | `bd89d64` | Not live-tested (no proxy cluster) |
| WI-3: Service tags | Not started | -- | -- |
| WI-4: NAP detection | Not started | -- | -- |
| Enhancement: Probe tests for network isolation | **Done** | `6262ae2` | Managed (block) + BYO (none) |
| Enhancement: NSG analyzer for network isolation | **Done** | `6a7e416` | Managed (block) + BYO (none) |
| Enhancement: Bootstrap ACR private DNS VNet link | **Done** | `f27f056` | Managed (block) + BYO (none) |
| Enhancement: Suppress noisy CLI findings | **Done** | `11a2f65` | Managed (block) + BYO (none) |
| Doc updates | **Done** | `1c32e53`, `cceca6c` | -- |

**Test clusters used:**
- `aks-wi1-managed` (managed VNet, AKS-managed ACR, outbound: block) in `aks-wi1-test-rg`
- `aks-wi1-byo` (BYO VNet `wi1-test-vnet`, BYO ACR `akswi1byoacr`, outbound: none) in `aks-wi1-test-rg`

---

## Scope

This release closes the high-priority gaps identified in the functionality and gaps analysis. Medium and low-priority gaps (dual-stack/IPv6, Virtual Nodes/ACI, LocalDNS, custom endpoint testing) are deferred to a future release.

---

## Work Items

### WI-1: Outbound Type `none` and `block` — ✅ IMPLEMENTED

**Status:** Implemented (`876816c`), design-reviewed and refined (`dc30e91`), live-tested on both managed VNet (block) and BYO VNet (none) clusters.

**Goal:** Recognize `none` and `block` outbound types, suppress false outbound findings, and validate bootstrap ACR configuration for network isolated clusters.

**Files modified:**
- `outbound_analyzer.py` -- outbound type dispatch, `_analyze_none_outbound()`, `_analyze_block_outbound()`
- `models.py` -- `OUTBOUND_TYPE_NONE`, `OUTBOUND_TYPE_BLOCK`, `OUTBOUND_TYPE_UNSUPPORTED`, `BOOTSTRAP_ACR_MISSING`

**What was implemented:**
1. Outbound type dispatch with `none` → `_analyze_none_outbound()`, `block` → `_analyze_block_outbound()`, and `else` for unrecognized types
2. `_analyze_none_outbound()`: INFO finding, checks bootstrap ACR presence, WARNING if missing
3. `_analyze_block_outbound()`: INFO finding, CRITICAL if bootstrap ACR missing (block requires it)
4. `_determine_effective_outbound()` updated for `none` ("user-managed") and `block` ("blocked by AKS")
5. Bootstrap profile read from `cluster_info["bootstrap_profile"]["container_registry_id"]`

**Design decision:** `NO_EXPLICIT_OUTBOUND_MECHANISM` warning was initially added then deliberately removed (`dc30e91`). Outbound types `none`/`block` are intentional configurations; warning about "no egress mechanism" produces false positives.

**Live testing results:**
- `aks-wi1-managed` (block): `OUTBOUND_TYPE_BLOCK` INFO, no false positives
- `aks-wi1-byo` (none): `OUTBOUND_TYPE_NONE` INFO, no false positives
- Both clusters with bootstrap ACR: no `BOOTSTRAP_ACR_MISSING` finding (correct)

---

### WI-2: HTTP Proxy Configuration Awareness — ✅ IMPLEMENTED

**Status:** Implemented (`bd89d64`). Not live-tested (no test cluster with HTTP proxy configured).

**Goal:** Detect `httpProxyConfig` in cluster properties and report the proxy egress path.

**Files modified:**
- `outbound_analyzer.py` -- `_check_http_proxy_config()` method
- `models.py` -- `HTTP_PROXY_CONFIGURED`

**What was implemented:**
1. `_check_http_proxy_config()` reads `cluster_info["http_proxy_config"]`
2. Extracts `httpProxy`, `httpsProxy`, `noProxy` list, `trustedCa` presence
3. Emits INFO finding `HTTP_PROXY_CONFIGURED` with proxy URLs and noProxy count
4. Proxy URLs included in finding details for diagnostic visibility

**Deferred:** NSG analysis proxy context notes and connectivity test proxy context were planned but not implemented. Proxy traffic still traverses NSGs normally, so no analysis changes are needed. Connectivity test `curl` commands inherit proxy environment variables from the node if configured.

---

### WI-3: Service Tags in Authorized IP Ranges

**Goal:** Detect service tag entries in `authorizedIpRanges`, avoid CIDR parsing errors, and report service tag constraints.

**Files to modify:**
- `api_server_analyzer.py` -- service tag detection and reporting
- `models.py` -- new FindingCode value

**Implementation:**

1. **Service tag detection** (`api_server_analyzer.py`, in `_analyze_authorized_ip_ranges()` loop around line 162):
   - Before calling `ipaddress.ip_network()`, check if the entry is a service tag
   - Detection: entry does not contain `/` (no CIDR notation) and is not a bare IP address
   - Known patterns: `AzureCloud`, `AzureCloud.eastus`, `ChaosStudio`, etc.
   - Regex: `^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)*$` (starts with letter, alphanumeric with optional dot-separated region)

2. **Service tag handling**:
   - Skip CIDR parsing for service tag entries (avoid `ValueError`)
   - Emit INFO finding: "Authorized IP ranges contain service tag: {tag_name}"
   - Warn if more than one service tag is detected (only one allowed per cluster)
   - Check for API Server VNet Integration incompatibility -- if VNet integration is active and service tags are present, emit WARNING

3. **Mixed range support**:
   - Process CIDR entries normally
   - Skip service tag entries in CIDR-specific analysis (range size, prefix length, private detection)
   - Include service tag entries in summary count

4. **New FindingCode** (`models.py`):
   - `SERVICE_TAG_IN_AUTH_RANGES` -- informational, service tag detected
   - `SERVICE_TAG_VNET_INTEGRATION_CONFLICT` -- warning, incompatible configuration

**Testing:**
- Unit test with mixed CIDR + service tag entries, verify no parsing errors
- Unit test with service tag + VNet integration, verify WARNING finding
- Unit test with multiple service tags, verify constraint warning

---

### WI-4: Node Auto-Provisioning (NAP) Detection

**Goal:** Detect NAP-enabled clusters and NAP-provisioned node pools, warn about potential diagnostic gaps.

**Files to modify:**
- `cluster_data_collector.py` -- NAP detection in cluster/agent pool data
- `orchestrator.py` -- NAP context in diagnostic workflow
- `models.py` -- new FindingCode value

**Implementation:**

1. **NAP detection** (`cluster_data_collector.py`, in `collect_cluster_info()` around line 161):
   - Check cluster properties for NAP enablement: `node_provisioning_profile` or `workload_auto_scaler_profile`
   - Check agent pools for NAP-created pools (may have specific labels or provisioning mode)
   - Store NAP status in `cluster_info["nap_enabled"]`

2. **VMSS discovery enhancement** (`cluster_data_collector.py`, `collect_vmss_info()`):
   - NAP-provisioned nodes create VMSS in the node resource group
   - Current VMSS enumeration should already discover them
   - Add label/tag detection to identify which VMSS are NAP-managed vs traditional
   - Tag detection: look for Karpenter-related tags on VMSS (e.g., `karpenter.sh/` prefixed tags)

3. **Diagnostic context** (`orchestrator.py`):
   - In phase 2 (node infrastructure), if NAP is enabled:
     - Emit INFO finding: "Cluster has Node Auto-Provisioning enabled"
     - Note that NAP-created nodes use dynamic subnets from AKSNodeClass
     - Warn if any NAP VMSS use subnets not covered by the extension's analysis

4. **RunCommand limitation note**:
   - NAP VMSS should support RunCommand (they are standard VMSS)
   - No special handling needed for connectivity tests

5. **New FindingCode** (`models.py`):
   - `NAP_ENABLED` -- informational, NAP is active on cluster
   - `NAP_SUBNET_NOT_ANALYZED` -- warning, NAP nodes may use subnets not in primary analysis

**Testing:**
- Unit test with NAP-enabled cluster profile, verify INFO finding
- Unit test with NAP VMSS using different subnet, verify WARNING

---

### WI-5: `defaultOutboundAccess` Retirement Awareness — ✅ IMPLEMENTED

**Status:** Implemented (`795efbd`), bug-fixed (`14c4ed4`), CLI output suppressed (`11a2f65`). Live-tested on both managed VNet (block) and BYO VNet (none) clusters.

**Goal:** Detect subnet `defaultOutboundAccess` setting and report private subnet status for visibility.

**Files modified:**
- `cluster_data_collector.py` -- `default_outbound_access` read via `getattr(subnet, 'default_outbound_access', None)`
- `outbound_analyzer.py` -- `_check_default_outbound_access()`, accepts `vnets_info` parameter
- `orchestrator.py` -- passes `vnets_info` to outbound analyzer, collects outbound findings
- `models.py` -- `DEFAULT_OUTBOUND_ACCESS_DISABLED`
- `report_generator.py` -- suppress from CLI output (both summary and detailed)

**What was implemented:**
1. Subnet property read in `collect_vnet_info()` — stores `default_outbound_access` per subnet
2. `_check_default_outbound_access()` emits per-subnet INFO findings when `False`
3. No WARNING for missing outbound mechanisms (intentional design)
4. CLI output suppression: `DEFAULT_OUTBOUND_ACCESS_DISABLED` hidden from console (both summary and `--details`) as it adds noise without actionable value. Preserved in JSON output for programmatic consumers.

**Bugs fixed:**
- `14c4ed4`: `vnets_info` was not passed to outbound analyzer; outbound findings were not collected in orchestrator

**Live testing results:**
- Managed VNet (block): 3 subnets with `defaultOutboundAccess: false` — correct INFO findings in JSON, clean CLI
- BYO VNet (none): 1 subnet with `defaultOutboundAccess: false` — correct INFO finding in JSON, clean CLI

---

## Implementation Order

The work items have dependencies that suggest this execution order:

```
WI-5 (defaultOutboundAccess)     -- foundation: subnet property reading
  |
  v
WI-1 (outbound none/block)      -- builds on: subnet awareness, adds bootstrap profile
  |
  v
WI-2 (HTTP proxy)               -- independent but benefits from outbound analysis context
  |
  v
WI-3 (service tags)             -- independent, self-contained in api_server_analyzer
  |
  v
WI-4 (NAP detection)            -- independent, self-contained in cluster_data_collector + orchestrator
```

Each work item should be a separate commit for clean review.

---

## Enhancements Beyond Original Plan

During implementation and live testing, several additional changes were identified and implemented:

### Enhancement: Probe Tests for Network Isolated Clusters (`6262ae2`)

For `none`/`block` clusters with a bootstrap ACR, the standard MCR DNS + internet connectivity probes are not meaningful (MCR may or may not work depending on user setup). Replaced with bootstrap ACR-specific probes:
- **Bootstrap ACR DNS Resolution**: `nslookup <acr>.azurecr.io` with `check_private_ip: True` to verify private endpoint resolution
- **Bootstrap ACR Connectivity**: `curl -v --insecure https://<acr>.azurecr.io/v2/` to verify HTTPS reachability
- Both marked `critical: True` (failures are actionable — error 211 is the #1 troubleshooting issue)
- ACR FQDN extracted from `bootstrapProfile.containerRegistryId`
- API server tests unchanged for all cluster types
- Tested on both managed VNet (block, 4/4 passed) and BYO VNet (none, 4/4 passed)

### Enhancement: NSG Analyzer for Network Isolation (`6a7e416`)

Adapted NSG compliance checks to avoid false positives on network isolated clusters:
- **Required rules**: For `none`/`block`, removed MCR and AzureCloud from required outbound rules. Only DNS (UDP 53) and NTP (UDP 123) remain required.
- **Blocking rule detection for `block`**: Skip outbound blocking analysis entirely (AKS inserts deny rules intentionally)
- **Blocking rule detection for `none`**: Only flag DNS blocking, not TCP 443 to MCR/AzureCloud
- **Private cluster API server rule**: Also skip for network isolated clusters (not just traditional private clusters)

### Enhancement: Bootstrap ACR Private DNS VNet Link Check (`f27f056`)

New CRITICAL check: verify that `privatelink.azurecr.io` DNS zone has a VNet link to the cluster's node VNet. Without this, ACR DNS resolution silently returns the public IP instead of the private endpoint IP.
- Handles BYO ACR (any RG/subscription) and AKS-managed ACR
- Targeted RG lookup (ACR RG, MC_ RG, cluster RG) with subscription-wide fallback
- Cross-subscription ACR support via dynamic `PrivateDnsManagementClient`
- For managed VNet clusters, discovers VNet from MC_ resource group
- New FindingCode: `BOOTSTRAP_ACR_DNS_NOT_LINKED`
- Negative-tested by removing VNet link → CRITICAL finding detected; restored → clean run

### Enhancement: Suppress Noisy CLI Findings (`11a2f65`)

`DEFAULT_OUTBOUND_ACCESS_DISABLED` per-subnet INFO findings add noise without actionable value in CLI output. Suppressed from both summary and `--details` modes. Preserved in JSON for programmatic consumers. When all visible findings are suppressed, shows "No issues detected" instead of empty findings section.

---

## Shared Changes

### models.py -- FindingCode Values

Implemented (added per-WI):

```
OUTBOUND_TYPE_NONE              (WI-1)
OUTBOUND_TYPE_BLOCK             (WI-1)
OUTBOUND_TYPE_UNSUPPORTED       (WI-1)
BOOTSTRAP_ACR_MISSING           (WI-1)
HTTP_PROXY_CONFIGURED           (WI-2)
DEFAULT_OUTBOUND_ACCESS_DISABLED (WI-5)
BOOTSTRAP_ACR_DNS_NOT_LINKED    (Enhancement)
```

Remaining (for WI-3 and WI-4):

```
SERVICE_TAG_IN_AUTH_RANGES       (WI-3)
SERVICE_TAG_VNET_INTEGRATION_CONFLICT (WI-3)
NAP_ENABLED                      (WI-4)
NAP_SUBNET_NOT_ANALYZED          (WI-4)
```

### Version Bump

Update `_version.py` from `0.2.0b2` to `0.3.0b1` after all work items are complete.

### setup.py

No new SDK dependencies expected. All data comes from existing AKS API responses (`azure-mgmt-containerservice`) which is provided by the CLI core, and `azure-mgmt-network` which is already declared.

---

## Out of Scope for v0.3.0

These gaps are deferred to future releases:

| Gap | Reason |
|-----|--------|
| Dual-stack / IPv6 | High effort, cross-cutting change across all analyzers |
| Virtual Nodes (ACI) | Medium effort, moderate adoption |
| AKS LocalDNS | Low impact, preview feature |
| Custom endpoint testing | New CLI parameter design needed |
| NTP validation | Low priority |
| BYO CNI | Niche adoption |

---

## Validation Checklist

- [x] `az aks net-diagnostics --help` loads successfully
- [x] `azdev linter aks-net-diagnostics` passes with 0 violations (verified at each commit)
- [ ] `azdev style aks-net-diagnostics` passes
- [ ] Unit tests pass for all new FindingCode paths
- [x] Existing functionality unchanged (verified via live testing against standard clusters)
- [ ] Version bumped to 0.3.0b1
- [ ] HISTORY.rst updated with changelog
- [x] Live-tested: managed VNet + AKS-managed ACR (outbound block)
- [x] Live-tested: BYO VNet + BYO ACR (outbound none)
- [x] Live-tested: probe tests 4/4 passed on both cluster types
- [x] Live-tested: negative test for missing ACR DNS VNet link → CRITICAL detected
- [ ] Push commits to remote
- [ ] Delete test resource group `aks-wi1-test-rg`
