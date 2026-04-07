# AKS Net-Diagnostics v0.3.0 Implementation Plan

**Branch:** `aks-net-diagnostics-v0.3.0`
**Base:** `aks-net-diagnostics-extension` (v0.2.0b2)
**Reference:** [net-diagnostics-functionality-and-gaps.md](net-diagnostics-functionality-and-gaps.md)

---

## Scope

This release closes the high-priority gaps identified in the functionality and gaps analysis. Medium and low-priority gaps (dual-stack/IPv6, Virtual Nodes/ACI, LocalDNS, custom endpoint testing) are deferred to a future release.

---

## Work Items

### WI-1: Outbound Type `none` and `block`

**Goal:** Recognize `none` and `block` outbound types, suppress false outbound findings, and validate bootstrap ACR configuration for network isolated clusters.

**Files to modify:**
- `outbound_analyzer.py` -- outbound type dispatch and effective outbound logic
- `models.py` -- new FindingCode values
- `cluster_data_collector.py` -- read `bootstrapProfile` from cluster properties

**Implementation:**

1. **Add outbound type dispatch** (`outbound_analyzer.py`, `analyze()` around line 135):
   - Add `elif outbound_type == "none":` branch calling new `_analyze_none_outbound()`
   - Add `elif outbound_type == "block":` branch calling new `_analyze_block_outbound()`
   - Add final `else:` clause to catch future unrecognized types with an INFO finding

2. **New handler: `_analyze_none_outbound()`**:
   - Report that the cluster has no AKS-managed egress
   - Suppress MCR/Azure service reachability warnings (user manages egress)
   - Check for `bootstrapProfile.containerRegistryResourceId` -- if present, report bootstrap ACR details
   - If no bootstrap ACR and no UDR, emit WARNING about potential lack of egress

3. **New handler: `_analyze_block_outbound()`**:
   - Report that AKS actively blocks all egress
   - Require `bootstrapProfile` -- if missing, emit CRITICAL finding
   - Suppress all outbound reachability checks (MCR, Azure services)

4. **Update `_determine_effective_outbound()`** (line 167-304):
   - Add cases for `none` and `block`
   - For `none`: effective outbound is "user-managed" or "no egress"
   - For `block`: effective outbound is "blocked by AKS"

5. **Read bootstrap profile** (`cluster_data_collector.py`):
   - Extract `bootstrap_profile` from cluster network profile
   - Store `containerRegistryResourceId` in `cluster_info`

6. **New FindingCode values** (`models.py`):
   - `OUTBOUND_TYPE_NONE` -- informational, cluster uses outbound type none
   - `OUTBOUND_TYPE_BLOCK` -- informational, cluster uses outbound type block
   - `OUTBOUND_TYPE_UNSUPPORTED` -- unrecognized outbound type
   - `BOOTSTRAP_ACR_MISSING` -- network isolated cluster without bootstrap ACR

**Testing:**
- Unit test with `outbound_type: "none"` cluster profile, verify no false MCR/Azure findings
- Unit test with `outbound_type: "block"` and missing bootstrap ACR, verify CRITICAL finding
- Unit test with unrecognized outbound type, verify INFO finding

---

### WI-2: HTTP Proxy Configuration Awareness

**Goal:** Detect `httpProxyConfig` in cluster properties, adjust NSG analysis context, and report the proxy egress path.

**Files to modify:**
- `outbound_analyzer.py` -- read and report proxy config
- `nsg_analyzer.py` -- adjust outbound rule analysis when proxy is present
- `models.py` -- new FindingCode value

**Implementation:**

1. **Read httpProxyConfig** (`outbound_analyzer.py`, `analyze()` after line 131):
   ```python
   http_proxy_config = self.cluster_info.get("http_proxy_config", {})
   ```

2. **New method: `_analyze_http_proxy_config()`**:
   - Extract `httpProxy`, `httpsProxy`, `noProxy`, `trustedCa` presence
   - Report proxy URLs in diagnostic output (mask credentials if present)
   - Add INFO finding: "Cluster uses HTTP proxy for outbound traffic"
   - Store proxy state in analysis result for downstream consumption

3. **NSG analysis adjustment** (`nsg_analyzer.py`):
   - When proxy is configured, add context note to outbound NSG findings
   - Do not suppress findings (proxy traffic still traverses NSGs to reach the proxy IP)
   - Add note: "This cluster uses an HTTP proxy. Outbound traffic routes through the proxy server rather than directly to destination IPs"

4. **Connectivity test context** (`connectivity_tester.py`):
   - Add proxy context to connectivity test output when `httpProxyConfig` is present
   - Existing `curl` commands may already use proxy via environment variables

5. **New FindingCode** (`models.py`):
   - `HTTP_PROXY_CONFIGURED` -- informational, cluster uses HTTP proxy

**Testing:**
- Unit test with `httpProxyConfig` present, verify INFO finding is generated
- Verify NSG findings include proxy context note
- Test with empty/null httpProxyConfig, verify no change in behavior

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

### WI-5: `defaultOutboundAccess` Retirement Awareness

**Goal:** Detect subnet `defaultOutboundAccess` setting and report private subnet status for visibility.

**Files to modify:**
- `cluster_data_collector.py` -- read subnet property
- `outbound_analyzer.py` -- cross-reference with outbound type
- `models.py` -- new FindingCode value

**Implementation:**

1. **Read subnet property** (`cluster_data_collector.py`, in VNet/subnet collection):
   - When collecting subnet details, extract `default_outbound_access` property
   - Store in subnet info dict: `"default_outbound_access": subnet.default_outbound_access`
   - Note: older subnets may not have this property set (defaults to `True` for pre-retirement)

2. **Outbound analysis cross-reference** (`outbound_analyzer.py`, new `_check_default_outbound_access()`):
   - If any cluster subnet has `defaultOutboundAccess == False`:
     - Emit INFO finding with subnet name and VNet name
     - Note that this is expected for clusters created after March 31, 2026, or BYO VNets with private subnets
   - No WARNING is emitted for missing outbound mechanisms. Outbound types `none` and `block` are intentional
     configurations where the user explicitly wants no internet outbound. The bootstrap ACR checks in the
     `none`/`block` handlers (WI-1) already provide actionable guidance when relevant.

3. **Informational output**:
   - In detailed output (`--details`), report `defaultOutboundAccess` status per subnet
   - Useful for visibility into the new default behavior

4. **New FindingCode** (`models.py`):
   - `DEFAULT_OUTBOUND_ACCESS_DISABLED` -- informational, subnet has private configuration

**Testing:**
- Unit test with `defaultOutboundAccess: false` subnet + loadBalancer outbound, verify INFO finding (no warning)
- Unit test with `defaultOutboundAccess: false` + outbound type `none`, verify INFO finding only (no false warning)

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

## Shared Changes

### models.py -- New FindingCode Values

All work items add FindingCode values. These should be added in a single batch or per-WI:

```
OUTBOUND_TYPE_NONE
OUTBOUND_TYPE_BLOCK
OUTBOUND_TYPE_UNSUPPORTED
BOOTSTRAP_ACR_MISSING
HTTP_PROXY_CONFIGURED
SERVICE_TAG_IN_AUTH_RANGES
SERVICE_TAG_VNET_INTEGRATION_CONFLICT
NAP_ENABLED
NAP_SUBNET_NOT_ANALYZED
DEFAULT_OUTBOUND_ACCESS_DISABLED
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

- [ ] `az aks net-diagnostics --help` loads successfully
- [ ] `azdev linter aks-net-diagnostics` passes with 0 violations
- [ ] `azdev style aks-net-diagnostics` passes
- [ ] Unit tests pass for all new FindingCode paths
- [ ] Existing functionality unchanged (regression test)
- [ ] Version bumped to 0.3.0b1
- [ ] HISTORY.rst updated with changelog
