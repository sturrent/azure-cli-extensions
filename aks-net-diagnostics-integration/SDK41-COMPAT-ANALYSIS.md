# SDK 41 Compatibility Analysis

## Problem Statement

Azure CLI 2.85.0 ships `azure-mgmt-containerservice` SDK **41.0.0**, which was regenerated with a new code generator. The `as_dict()` method now returns a fundamentally different structure compared to SDK **40.2.0** (CLI 2.83.0):

| Aspect | SDK 40 (CLI ≤2.83) | SDK 41 (CLI ≥2.85) |
|--------|--------------------|--------------------|
| Key naming | `snake_case` | `camelCase` |
| Structure | Flat | Nested under `properties` |
| Example | `d["agent_pool_profiles"]` | `d["properties"]["agentPoolProfiles"]` |
| Example | `d["node_resource_group"]` | `d["properties"]["nodeResourceGroup"]` |
| Example | `d["network_profile"]["outbound_type"]` | `d["properties"]["networkProfile"]["outboundType"]` |

### Observed Symptoms on CLI 2.85

```
No agent pools found in cluster configuration
No managed resource group found in cluster info
[WARNING] NO_OUTBOUND_IPS - No outbound IP addresses detected for loadBalancer outbound type
```

All caused by `.get("snake_case_key")` returning `None` on the new camelCase dict.

---

## Approaches

### Approach A: Single version with normalization layer

Add a `_normalize_sdk_dict()` function in `_to_dict()` that detects the SDK version format and normalizes to snake_case flat structure.

**Implementation:**
- Modify `_to_dict()` in `cluster_data_collector.py` (~50 lines)
- Detect `properties` envelope → flatten
- Detect camelCase keys → convert to snake_case
- All downstream code remains unchanged

**Pros:**
- Single codebase, single wheel, single release
- Users on both CLI versions get the same extension version
- Simplest for end users (one install command regardless of CLI version)
- The normalization is isolated to one function — if the SDK changes again, only one place to fix

**Cons:**
- Implicit format detection could break if a future SDK changes again in an unexpected way
- Need to verify camelCase→snake_case conversion covers all keys used across all modules
- Adds complexity to `_to_dict()` — a function that was previously trivial
- Testing must cover both SDK formats (but we already have no automated tests)

**Risk:** Medium-low. The camelCase-to-snake_case conversion is mechanical and well-understood. The envelope flattening is a single `if` check.

---

### Approach B: Separate versions for old and new CLI

Keep **v0.3.0b1** as-is for CLI ≤2.83 (SDK ≤40). Create a new version (e.g., **v0.3.1b1** or **v0.4.0b1**) that targets CLI ≥2.85 (SDK ≥41) by updating all `.get()` calls to use the new structure.

**Implementation:**
- Create a new branch (e.g., `aks-net-diagnostics-v0.3.1` or `aks-net-diagnostics-v0.4.0`)
- Update all `.get()` calls across all modules to use camelCase + `properties` nesting
- Or: switch to direct attribute access (`cluster.agent_pool_profiles`) instead of `as_dict()` dicts
- Bump version, rebuild wheel, create new release

**Pros:**
- Clean separation — each version targets a known, tested SDK
- No runtime format detection or conversion logic
- v0.3.0b1 remains stable and unchanged for existing users

**Cons:**
- **Two codebases to maintain** — bug fixes, new features need to be applied to both
- Users must know which CLI version they're running to pick the right extension
- The Azure CLI Extensions index only supports one version per extension — can't publish both
- If CLI 2.85 becomes the default (automatic updates), v0.3.0b1 silently breaks for everyone
- More releases, more wheels, more GitHub releases to manage
- The "old" version becomes dead code once CLI 2.85 adoption grows

**Risk:** High maintenance burden. CLI auto-updates mean the old SDK version will age out quickly.

---

### Approach C: Drop `as_dict()` — use SDK attribute access directly

Instead of converting SDK objects to dicts via `as_dict()`, access attributes directly (e.g., `cluster.agent_pool_profiles`, `cluster.network_profile.outbound_type`). The Python SDK preserves snake_case attribute access across versions.

**Implementation:**
- Major refactor: replace all `cluster_info.get("key")` patterns with attribute access
- Pass SDK objects instead of dicts through the codebase
- Add `getattr()` with defaults for optional fields

**Pros:**
- No dependency on `as_dict()` serialization format
- SDK guarantees backward-compatible attribute names
- More Pythonic — type hints, IDE completion

**Cons:**
- **Large refactor** across every module (cluster_data_collector, orchestrator, nsg_analyzer, outbound_analyzer, dns_analyzer, connectivity_tester, misconfiguration_analyzer)
- Would need to also refactor VMSS/VM/NIC/NSG handling (those use `_to_dict()` too)
- Breaks the current architecture where analyzers receive plain dicts
- High risk of introducing regressions across all 21 tested scenarios
- The `--json-report` export depends on dict serialization

**Risk:** High. Scope is too large for a targeted fix.

---

### Approach D: Pin SDK version in extension metadata

Declare `azure-mgmt-containerservice~=40.0` in `setup.py` to force the older SDK, even when the host CLI has SDK 41.

**Implementation:**
- Update `setup.py` dependency pin
- Rebuild wheel

**Pros:**
- Zero code changes
- Guaranteed consistent behavior

**Cons:**
- **May not work** — CLI extensions share the host Python environment; pip may refuse to install a conflicting version
- Could break other CLI commands that depend on SDK 41
- Not a sustainable strategy — locks us to an aging SDK indefinitely
- Goes against Azure CLI extension best practices

**Risk:** High. Likely not viable due to shared environment constraints.

---

## Comparison Matrix

| Criteria | A: Normalize | B: Separate versions | C: Attribute access | D: Pin SDK |
|----------|-------------|---------------------|--------------------| -----------|
| Code changes | ~50 lines, 1 file | All modules, 2 branches | All modules, deep refactor | 1 line in setup.py |
| Maintenance burden | Low | High (2 codebases) | Medium (ongoing) | Low but fragile |
| User experience | Transparent | Confusing (which version?) | Transparent | May conflict |
| Risk of regressions | Low | Low per version | High | Unknown |
| Future-proof | Good | Poor | Best | Poor |
| Time to implement | Hours | Days | Week+ | Minutes |
| Viable for upstream PR | Yes | No (single index entry) | Yes (but large diff) | No |

---

## Recommendation

**Approach A (normalization layer)** is the best balance of risk, effort, and sustainability:

1. Isolated change — only `_to_dict()` in `cluster_data_collector.py` needs modification
2. Both SDK formats produce identical output for all downstream consumers
3. Single version works everywhere — no user confusion
4. Compatible with the upstream Azure CLI Extensions repo model (single version per extension)
5. If the SDK changes again, only one function to update

### Suggested implementation

```python
def _camel_to_snake(name: str) -> str:
    """Convert camelCase key to snake_case."""
    s1 = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    return re.sub(r'([a-z\d])([A-Z])', r'\1_\2', s1).lower()

def _normalize_sdk_dict(d):
    """Flatten ARM envelope and convert camelCase to snake_case."""
    if isinstance(d, list):
        return [_normalize_sdk_dict(item) for item in d]
    if not isinstance(d, dict):
        return d
    # Flatten properties envelope (SDK >=41)
    if 'properties' in d and isinstance(d['properties'], dict):
        props = d.pop('properties')
        d.update(props)
    return {
        _camel_to_snake(k): _normalize_sdk_dict(v)
        for k, v in d.items()
    }
```

Then call `_normalize_sdk_dict()` inside `_to_dict()` after `as_dict()`.

### Validation plan

1. Test normalization function with both SDK 40 and SDK 41 mock outputs
2. Run the extension from the azdev venv (SDK 40) against test clusters
3. Run the extension from system CLI 2.85 (SDK 41) against the same clusters
4. Compare JSON reports for parity

---

## Upstream Reference: Azure CLI PR #32955

### Overview

The AKS team merged [PR #32955](https://github.com/Azure/azure-cli/pull/32955) in March 2026: **"{AKS} Vendor new SDK and bump API version to 2026-01-01"**. This PR:

- Updated `azure-mgmt-containerservice` from 40.x to 41.0.0
- Changed 227 files across the `acs` module in azure-cli core
- Bumped API version from `2025-04-02-preview` to `2026-01-01`
- Shipped in Azure CLI **2.85.0** (April 2026)

### Key Code Migration Patterns

The AKS team's code does **not** use `as_dict()` — it accesses SDK model attributes directly. Even so, the SDK 41 regeneration required significant changes:

| Pattern | SDK 40 (Before) | SDK 41 (After) |
|---------|-----------------|----------------|
| Module path | `azure.mgmt.containerservice.v*._managed_clusters_operations` | `azure.mgmt.containerservice._operations` |
| Nested property access | `instance.type_properties_type` | `instance.properties.type_properties_type` |
| Delete attribute | `delattr(mc, attr)` | `mc.pop(attr, None)` |
| List model attributes | `vars(mc)` | `attribute_list(mc)` from `azure.core.serialization` |
| Etag handling | `if_match=etag, if_none_match=...` | `build_etag_kwargs(etag)` helper |
| API server access | `additional_properties['enableVnetIntegration']` | `mc.api_server_access_profile.enable_vnet_integration` |
| Removed field | `docker_bridge_cidr` available | `docker_bridge_cidr` removed entirely |

### Why Our Extension Is Uniquely Affected

1. **The AKS CLI team does NOT use `as_dict()`** — they use direct attribute access on SDK objects, which the SDK maintains backward compatibility for (snake_case attributes still work)
2. **Our extension converts everything to dicts via `as_dict()`** — this is a serialization path that changed fundamentally in SDK 41's new code generator
3. **Other AKS extensions** (e.g., `aks-preview`) vendor their own SDK copy and update in lockstep, so they never encounter the mismatch
4. **No open issues** were filed about `as_dict()` breaking — because no other extensions rely on it for data access

### Implications for Approach A

The PR #32955 research **reinforces Approach A** as the correct fix:

- We cannot adopt the AKS team's direct-attribute-access pattern without a full refactor (Approach C) — too risky
- The AKS team's changes (227 files) show that SDK 41 is a major regeneration, not a minor tweak — normalization is a pragmatic response
- The `properties` envelope and camelCase keys in `as_dict()` are consistent patterns from the new ARM code generator — our normalization logic will be stable
- If we ever upstream this extension, the normalized dict approach is compatible with the Azure CLI extension model

### Recommendation Update

Approach A remains the recommended fix. The PR #32955 analysis confirms:
- The `as_dict()` format change is an artifact of the new SDK code generator, not an intentional API design choice
- Direct attribute access (Approach C) would require changes comparable in scope to PR #32955's 227-file update
- Normalization is the lowest-risk path to support both SDK 40 and SDK 41 from a single codebase

---

**Created:** April 13, 2026
**Updated:** April 13, 2026 — Added PR #32955 upstream analysis
