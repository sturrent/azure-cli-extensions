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
| WI-2: HTTP proxy awareness | **Done** | `bd89d64`, `0c225e3` | Proxy cluster (3 breakage scenarios) |
| WI-3: Service tags | **Done** | `124677a` | Service tag cluster (single + multi) |
| WI-4: NAP detection | Not started | -- | -- |
| Enhancement: Probe tests for network isolation | **Done** | `6262ae2` | Managed (block) + BYO (none) |
| Enhancement: NSG analyzer for network isolation | **Done** | `6a7e416` | Managed (block) + BYO (none) |
| Enhancement: Bootstrap ACR private DNS VNet link | **Done** | `f27f056` | Managed (block) + BYO (none) |
| Enhancement: Suppress noisy CLI findings | **Done** | `11a2f65` | Managed (block) + BYO (none) |
| Enhancement: Proxy diagnostics (VNet, NSG, probes) | **Done** | `0c225e3` | Proxy cluster (3 breakage scenarios) |
| Doc updates | **Done** | `1c32e53`, `cceca6c` | -- |

**Test clusters used:**
- `aks-wi1-managed` (managed VNet, AKS-managed ACR, outbound: block) in `aks-wi1-test-rg`
- `aks-wi1-byo` (BYO VNet `wi1-test-vnet`, BYO ACR `akswi1byoacr`, outbound: none) in `aks-wi1-test-rg`
- `aks-proxy` (HTTP proxy via VNet peering, outbound: loadBalancer) in `aks-proxy-rg` — AKS VNet `aks-proxy-vnet` (10.100.0.0/16) peered to `proxy-svc-vnet` (172.12.0.0/16) in `proxy-svc-rg`, proxy VM at 172.12.0.4:8080
- `aks-wi3-svc-tag` (service tags in authorized IP ranges, outbound: loadBalancer) in `aks-wi3-test-rg`

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

**Status:** Implemented (`bd89d64`), enhanced with actionable proxy diagnostics (`0c225e3`). Live-tested on dedicated proxy cluster with three breakage scenarios.

**Goal:** Detect `httpProxyConfig` in cluster properties, validate proxy reachability, add NSG compliance rules, and run active probe tests through the proxy.

**Files modified:**
- `outbound_analyzer.py` -- `_check_http_proxy_config()`, `_check_proxy_reachability()`, `_parse_proxy_url()`, `_get_remote_vnet_prefixes()`
- `nsg_analyzer.py` -- `_get_proxy_required_rule()`, `_blocks_proxy_traffic()`
- `connectivity_tester.py` -- `_build_proxy_tests()`
- `models.py` -- `HTTP_PROXY_CONFIGURED`, `PROXY_NOT_REACHABLE`

**What was implemented:**

*Phase 1 — Detection (`bd89d64`):*
1. `_check_http_proxy_config()` reads `cluster_info["http_proxy_config"]`
2. Extracts `httpProxy`, `httpsProxy`, `noProxy` list, `trustedCa` presence
3. Emits INFO finding `HTTP_PROXY_CONFIGURED` with proxy URLs and noProxy count
4. Proxy URLs included in finding details for diagnostic visibility

*Phase 2 — Actionable diagnostics (`0c225e3`):*

5. **Proxy VNet reachability** (`outbound_analyzer.py`):
   - `_parse_proxy_url()` extracts IP and port from proxy URL (handles `http://`, `https://`, with/without port)
   - `_check_proxy_reachability()` validates proxy IP is within node VNet address spaces or reachable via VNet peering
   - `_get_remote_vnet_prefixes()` resolves peered VNet address prefixes from peering resource IDs
   - Emits `PROXY_NOT_REACHABLE` CRITICAL if proxy IP not within any reachable address space
   - Return dict includes `proxy_ip` and `proxy_port` for downstream consumers (NSG, probes)

6. **NSG proxy compliance** (`nsg_analyzer.py`):
   - `_get_proxy_required_rule()` parses proxy URL and returns required outbound rule dict (`AKS_HTTP_Proxy`, TCP, dest=proxy_ip, port=proxy_port)
   - Added to `_get_required_aks_rules()` after API server rule when `http_proxy_config` is present
   - `_blocks_proxy_traffic()` detects deny rules targeting proxy IP:port specifically
   - Integrated into `_blocks_aks_traffic()` for both network-isolated and standard clusters

7. **Proxy probe test** (`connectivity_tester.py`):
   - `_build_proxy_tests()` builds "HTTP Proxy Connectivity" test when `http_proxy_config` is present
   - Test uses `curl -v --max-time 15 --proxy-insecure -x {proxy_url} https://mcr.microsoft.com/v2/`
   - Expected keywords: `["200", "401", "407", "HTTP/"]` (any proxy/server response = reachable)
   - Marked `critical: True`, runs FIRST in test list (before registry and API tests)

**Live testing results (proxy cluster `aks-proxy` in `aks-proxy-rg`):**

| Scenario | Finding | Probes |
|----------|---------|--------|
| Working proxy (peering intact) | 0 critical, 2 INFO | 5/5 passed |
| NSG deny rule on proxy IP:port | CRITICAL `NSG_BLOCKING_AKS_TRAFFIC` | -- |
| Broken VNet peering to proxy VNet | CRITICAL `PROXY_NOT_REACHABLE` | 1 FAILED (timeout), 4 passed |

**Test cluster topology:**
- AKS VNet `aks-proxy-vnet` (10.100.0.0/16) in `aks-proxy-rg`
- Proxy VNet `proxy-svc-vnet` (172.12.0.0/16) in `proxy-svc-rg`
- VNet peering: `aks-to-svc` ↔ `svc-to-aks`
- Squid proxy VM at 172.12.0.4:8080

---

### WI-3: Service Tags in Authorized IP Ranges — ✅ IMPLEMENTED

**Status:** Implemented (`124677a`). Live-tested on dedicated cluster with single and multiple service tags.

**Goal:** Detect service tag entries in `authorizedIpRanges`, avoid CIDR parsing errors, and report service tag constraints.

**Files modified:**
- `api_server_analyzer.py` -- `_is_service_tag()`, `_analyze_service_tags()`, updated `_analyze_authorized_ip_ranges()`
- `misconfiguration_analyzer.py` -- removed redundant `API_RESTRICTED_ACCESS` INFO finding
- `models.py` -- `SERVICE_TAG_IN_AUTH_RANGES`, `SERVICE_TAG_VNET_INTEGRATION_CONFLICT`

**What was implemented:**
1. `_is_service_tag()` static method using regex `^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)*$` to distinguish service tags (e.g. `AzureCloud`, `Storage.WestUS`) from CIDRs and bare IPs. Rejects entries with `/` (CIDR) or `:` (IPv6), and entries starting with digits.
2. `_analyze_authorized_ip_ranges()` separates service tags from CIDR ranges before processing. Service tags skip CIDR security analysis entirely (no false "Invalid IP range format" warnings).
3. `_analyze_service_tags()` emits three findings:
   - INFO when service tags present (preview feature requiring `EnableServiceTagAuthorizedIPPreview` feature flag)
   - WARNING when multiple service tags detected (only 1 allowed per cluster per AKS docs)
   - WARNING when service tags + VNet Integration (incompatible per AKS docs)
4. Outbound IP authorization check skipped when service tags present (tags like `AzureCloud` cover all Azure IPs including cluster outbound IPs — check is meaningless).
5. Removed redundant `API_RESTRICTED_ACCESS` INFO finding from `misconfiguration_analyzer.py` — the WARNING "API server access restricted" from `security_findings` already covers it.

**Prerequisites for live testing:**
- `aks-preview` CLI extension (v19.0.0b29+)
- `EnableServiceTagAuthorizedIPPreview` feature flag registered
- `az provider register --namespace Microsoft.ContainerService` after flag registration

**Live testing results (cluster `aks-wi3-svc-tag` in `aks-wi3-test-rg`):**

| Scenario | Findings |
|----------|----------|
| Single service tag (`AzureCloud` + CIDR) | 2: INFO service tag (preview) + WARNING restricted access |
| Multiple service tags (`AzureCloud` + `ChaosStudio` + CIDR) | 3: INFO service tag + WARNING multiple tags + WARNING restricted |
| CIDR-only (regression check, no cluster) | Outbound IP authorization check preserved |

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

### Enhancement: Actionable Proxy Diagnostics (`0c225e3`)

HTTP proxy detection (WI-2 Phase 1) only reported an INFO finding — not actionable for troubleshooting. Phase 2 adds three enhancements validated via deliberate breakage testing:

1. **Proxy VNet reachability** (`outbound_analyzer.py`): Validates proxy IP is within the node VNet or reachable via VNet peering. Emits `PROXY_NOT_REACHABLE` CRITICAL when proxy is unreachable. Parses proxy URL to extract IP/port, resolves peered VNet prefixes via ARM peering resource IDs.

2. **NSG proxy compliance** (`nsg_analyzer.py`): Adds proxy IP:port as a required outbound rule (`AKS_HTTP_Proxy`). Detects deny rules specifically targeting proxy traffic. Works for both network-isolated and standard clusters.

3. **Proxy connectivity probe** (`connectivity_tester.py`): Adds "HTTP Proxy Connectivity" test that curls MCR through the proxy. Runs FIRST in test list to surface proxy failures before downstream tests. Accepts any HTTP response (200/401/407) as success since it proves network path works.

**Breakage test results:**
- NSG deny rule `DenyProxyOutbound` (priority 100, TCP, dest 172.12.0.4:8080) → CRITICAL `NSG_BLOCKING_AKS_TRAFFIC` detected immediately
- VNet peering deletion (`aks-to-svc`) → CRITICAL `PROXY_NOT_REACHABLE` + probe `[FAILED]` with `curl error (28): Connection timed out`
- Both restored → clean run (0 critical, 5/5 probes passed)

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
PROXY_NOT_REACHABLE             (WI-2 / Enhancement)
DEFAULT_OUTBOUND_ACCESS_DISABLED (WI-5)
BOOTSTRAP_ACR_DNS_NOT_LINKED    (Enhancement)
SERVICE_TAG_IN_AUTH_RANGES      (WI-3)
SERVICE_TAG_VNET_INTEGRATION_CONFLICT (WI-3)
```

Remaining (for WI-4):

```
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
- [x] Live-tested: proxy cluster — working, NSG deny, broken peering (3 breakage scenarios)
- [x] Live-tested: service tag in authorized IP ranges — single tag, multiple tags
- [ ] Push commits to remote
- [ ] Delete test resource groups (`aks-wi3-test-rg`)
