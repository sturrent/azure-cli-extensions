# AKS Net-Diagnostics Extension: Functionality and Gaps

**Extension Version:** v0.2.0b2
**Last Updated:** April 6, 2026
**Based on:** Microsoft public documentation and source code review

---

## Table of Contents

1. [Purpose](#purpose)
2. [Network Plugin Support](#network-plugin-support)
3. [Outbound Connectivity Types](#outbound-connectivity-types)
4. [Cluster Access Models](#cluster-access-models)
5. [API Server Security](#api-server-security)
6. [NSG Analysis](#nsg-analysis)
7. [DNS Analysis](#dns-analysis)
8. [Route Analysis](#route-analysis)
9. [Node Infrastructure](#node-infrastructure)
10. [Connectivity Testing](#connectivity-testing)
11. [Advanced Networking Features](#advanced-networking-features)
12. [Platform Changes and Retirements](#platform-changes-and-retirements)
13. [Permission Handling](#permission-handling)
14. [Output and Reporting](#output-and-reporting)
15. [Gap Summary and Prioritization](#gap-summary-and-prioritization)

---

## Purpose

This document maps the extension's current diagnostic coverage against the full set of AKS networking features documented in [Microsoft Learn](https://learn.microsoft.com/azure/aks/concepts-network). It identifies functional gaps that could affect diagnostic accuracy or completeness as AKS continues to evolve.

### Legend

| Symbol | Meaning |
|--------|---------|
| Supported | Implemented and tested |
| Partial | Partially implemented or not fully validated |
| Gap | Not implemented |

---

## Network Plugin Support

**Reference:** [AKS CNI networking overview](https://learn.microsoft.com/azure/aks/concepts-network-cni-overview)

| Network Plugin | Status | Extension Behavior |
|----------------|--------|-------------------|
| Azure CNI (node subnet) | Supported | Full VNet/subnet analysis, NSG validation, IP allocation checks |
| Azure CNI Overlay | Supported | Pod CIDR NSG validation via `_check_overlay_pod_cidr_rules()`, overlay mode detection |
| Azure CNI (pod subnet) | Supported | Dual-subnet detection, enhanced CNI mode display |
| Kubenet | Supported | Basic detection; limited validation since Kubenet uses bridge networking |
| Azure CNI Powered by Cilium | Supported | Cilium operates at the in-cluster eBPF layer and does not change Azure infrastructure networking. The extension's checks (VNets, NSGs, routing, DNS, outbound) are identical for Cilium and non-Cilium clusters |
| BYO CNI | Gap | No detection or custom CNI-specific validation |

### Note on Cilium Dataplane

Azure CNI Powered by Cilium (`networkDataplane: cilium`) replaces iptables/kube-proxy with eBPF for in-cluster packet processing (pod-to-pod, service routing, network policies). From the Azure infrastructure perspective, Cilium clusters have identical VNet, NSG, routing, DNS, and outbound configurations as non-Cilium clusters. All 10 diagnostic phases operate at the Azure infrastructure layer and are unaffected by the Cilium dataplane.

Cilium-specific features such as eBPF network policies, FQDN filtering, L7 policies, WireGuard encryption, and mTLS (via Advanced Container Networking Services) are Kubernetes-level constructs and outside the extension's infrastructure-focused scope.

---

## Outbound Connectivity Types

**Reference:** [Customize cluster egress with outbound types](https://learn.microsoft.com/azure/aks/egress-outboundtype)

| Outbound Type | Status | Extension Behavior |
|---------------|--------|-------------------|
| `loadBalancer` | Supported | Public IP extraction from LB frontend configs, outbound rules, effective IP detection |
| `managedNATGateway` | Supported | NAT Gateway detection in node resource group, public IP and prefix extraction |
| `userAssignedNATGateway` | Supported | Subnet attachment checks, BYO NAT Gateway, user-managed IP detection |
| `userDefinedRouting` | Supported | Route table analysis, virtual appliance detection, UDR impact classification |
| `none` | Gap | Not handled. Extension does not recognize this outbound type or adapt its analysis accordingly |
| `block` (preview) | Gap | Not handled. Extension does not recognize this outbound type |
| HTTP proxy (`httpProxyConfig`) | Gap | Not detected. Extension does not check for proxy configuration or adjust analysis accordingly |

### Gap Details: Outbound Type `none` and `block`

Network isolated clusters use outbound type `none` (GA) or `block` (preview) combined with `--bootstrap-artifact-source Cache` and a private ACR for image pulls.

- **Outbound type `none`**: AKS does not set up any egress paths. The user configures them manually or operates without outbound internet access.
- **Outbound type `block`**: AKS actively blocks all egress traffic from the cluster.

The extension currently does not:
- Detect `none` or `block` as valid outbound types
- Adjust outbound connectivity expectations (MCR reachability, Azure service access)
- Validate bootstrap ACR configuration (`bootstrapProfile.containerRegistryResourceId`)
- Check private endpoint connectivity to the bootstrap ACR

**Impact:** High. Network isolated clusters are increasingly common for security-sensitive environments. The extension may produce false findings about missing outbound connectivity.

### Gap Details: HTTP Proxy Configuration

**Reference:** [HTTP proxy support in AKS](https://learn.microsoft.com/azure/aks/http-proxy)

AKS clusters can be configured with an HTTP proxy for outbound internet access via `httpProxyConfig` (available in the AKS API response under `properties.httpProxyConfig`). When configured, node and pod traffic is routed through the proxy server rather than directly through NSG-allowed paths.

The extension currently does not:
- Detect `httpProxyConfig` in the cluster properties
- Account for proxy-routed egress when analyzing NSG rules (may flag missing outbound rules that are unnecessary with a proxy)
- Adjust outbound connectivity expectations (MCR, Azure services) when a proxy is in use
- Report the effective egress path through the proxy in diagnostic output
- Consider `noProxy` entries when evaluating which traffic bypasses the proxy

**Impact:** Medium. Clusters using HTTP proxy may receive false NSG findings about missing outbound rules. Connectivity tests run via RunCommand may succeed transparently through the proxy, but the extension does not explain this in its output.

### NAT Gateway StandardV2

**Reference:** [StandardV2 NAT Gateway](https://learn.microsoft.com/azure/nat-gateway/nat-overview#standardv2-nat-gateway)

The extension detects NAT Gateway and extracts public IPs and prefixes. It does not differentiate between Standard and StandardV2 SKUs. StandardV2 is zone-redundant by default and offers higher bandwidth.

**Impact:** Low. The diagnostic output is still valid; the SKU distinction is informational only.

---

## Cluster Access Models

**Reference:** [Plan control plane networking](https://learn.microsoft.com/azure/aks/plan-control-plane-networking)

| Cluster Type | Status | Extension Behavior |
|--------------|--------|-------------------|
| Public cluster | Supported | Standard API server access validation |
| Private cluster (Private Link) | Supported | Private DNS zone validation, VNet link checks, private endpoint detection |
| Private cluster (API Server VNet Integration) | Supported | VNet integration detection, delegated subnet validation |
| Network isolated cluster | Gap | Basic structure recognized but no specific validation for bootstrap ACR, private connectivity, or outbound restrictions |

### Gap Details: Network Isolated Clusters

Network isolated clusters combine private cluster mode (Private Link or API Server VNet Integration) with outbound type `none`/`block` and a private ACR bootstrap. The extension does not validate:

- Bootstrap ACR resource and its private endpoint
- ACR cache rules for AKS-managed images
- Private DNS resolution for the bootstrap ACR
- Whether the cluster operates entirely without internet egress

**Impact:** High. Growing adoption for zero-trust and compliance-driven deployments.

---

## API Server Security

**Reference:** [API server authorized IP ranges](https://learn.microsoft.com/azure/aks/api-server-authorized-ip-ranges) and [Service tags for authorized IPs (preview)](https://learn.microsoft.com/azure/aks/api-server-service-tags)

| Feature | Status | Extension Behavior |
|---------|--------|-------------------|
| Authorized IP ranges (CIDR) | Supported | Detection, conflict analysis, outbound IP inclusion validation |
| Outbound IP + authorized IP correlation | Supported | Warns if cluster outbound IPs are not included in authorized ranges |
| UDR + authorized IP conflict detection | Supported | Detects when UDR overrides outbound IP, making authorized range validation unreliable |
| Client IP authorization | Supported | Validates current client context |
| **Service tags in authorized IP ranges (preview)** | **Gap** | **Not handled. The extension parses authorized IP ranges as CIDR strings. Service tag entries (e.g., `AzureCloud`) are not recognized, resolved, or validated** |
| Service tag + CIDR mixed ranges | Gap | No parsing logic for mixed entries containing both CIDRs and service tag names |
| API Server VNet Integration incompatibility | Gap | Service tags are not compatible with API Server VNet Integration. Extension does not warn about this |

### Gap Details: Service Tags in Authorized IP Ranges

This is a preview feature (`EnableServiceTagAuthorizedIPPreview` feature flag) that allows using Azure service tags (e.g., `AzureCloud`, `ChaosStudio`) instead of individual IP ranges in `--api-server-authorized-ip-ranges`.

Key constraints from the documentation:
- Only one service tag is allowed per cluster
- Not compatible with API Server VNet Integration
- Service tags can be mixed with individual CIDR ranges

The extension currently:
- Parses `authorizedIpRanges` as a list of CIDR strings
- Does not detect service tag names (which are not in CIDR format)
- May produce false warnings or errors when encountering a service tag entry
- Does not validate compatibility with API Server VNet Integration

**Impact:** Medium. Preview feature with growing adoption. Incorrect parsing could produce confusing output.

---

## NSG Analysis

**Reference:** [Network security groups with AKS](https://learn.microsoft.com/azure/aks/concepts-network#network-security-groups)

| Check | Status | Extension Behavior |
|-------|--------|-------------------|
| Required AKS outbound rules (MCR, Azure Cloud, DNS, NTP) | Supported | Full validation with service tag awareness |
| Required inbound rules (inter-node, LB probes) | Supported | Port 10250 and health probe validation |
| Azure CNI Overlay pod CIDR rules | Supported | Node-to-Pod and Pod-to-Pod traffic validation |
| Blocking rule detection with priority analysis | Supported | Priority-based override detection |
| Service tag semantics | Supported | VirtualNetwork, AzureLoadBalancer, Internet tags |
| NIC-level NSGs | Supported | Both subnet and NIC NSGs analyzed |
| API server subnet NSG (VNet Integration) | Supported | Delegated subnet NSG checks |
| IPv6 NSG rules | Gap | No IPv6 rule analysis |
| Network policy interaction | Out of scope | Network policies are Kubernetes-level constructs, not Azure infrastructure |

---

## DNS Analysis

**Reference:** [Private DNS zones with AKS](https://learn.microsoft.com/azure/aks/private-clusters#configure-a-private-dns-zone)

| Check | Status | Extension Behavior |
|-------|--------|-------------------|
| Azure default DNS detection | Supported | Identifies when default DNS is in use |
| Custom DNS server configuration | Supported | Warns about reachability and forwarding |
| Private DNS zone (system-managed) | Supported | Zone detection and VNet link validation |
| BYO Private DNS zone | Supported | Cross-subscription support |
| VNet links to private DNS | Supported | Validates links exist for cluster VNet |
| AKS LocalDNS (preview) | Gap | No detection of node-level DNS caching (169.254.10.10/11) |
| CoreDNS configuration | Gap | Pod-level DNS configuration not validated |

### Gap Details: AKS LocalDNS

AKS LocalDNS is a preview feature that adds a node-level DNS caching proxy. DNS queries go to 169.254.10.10 or 169.254.10.11 instead of CoreDNS pods. This could affect connectivity test results (DNS resolution tests from nodes) if the extension expects standard CoreDNS behavior.

**Impact:** Low. Preview feature. DNS resolution tests would still succeed; the path is different but transparent.

---

## Route Analysis

| Check | Status | Extension Behavior |
|-------|--------|-------------------|
| Default route (0.0.0.0/0) detection | Supported | Next-hop type analysis |
| Virtual appliance routes | Supported | NVA/firewall detection |
| VirtualNetworkGateway routes | Supported | ExpressRoute/VPN impact analysis |
| Route impact classification (critical/high/medium/low) | Supported | Per-traffic-type severity |
| BGP propagation status | Supported | Route propagation flags checked |
| MCR/Azure services blocking routes | Supported | Traffic-type-specific analysis |
| IPv6 routes | Gap | No IPv6 route analysis |

---

## Node Infrastructure

| Infrastructure | Status | Extension Behavior |
|---------------|--------|-------------------|
| VMSS (standard node pools) | Supported | Full NIC/subnet/NSG analysis, RunCommand for probes |
| Virtual Machines node pools | Supported | VM NIC discovery, subnet enrichment |
| Mixed VMSS+VM clusters | Supported | Both types handled in parallel |
| Node Auto-Provisioning (NAP / Karpenter) | Gap | No NAP detection or Karpenter-provisioned node analysis |
| Virtual Nodes (ACI) | Gap | No ACI subnet or virtual node validation |
| GPU/specialized node pools | Supported | GPU node pools use the same Azure infrastructure networking as standard pools. VNet, NSG, routing, and outbound checks are identical |

### Gap Details: Node Auto-Provisioning (NAP)

NAP uses Karpenter to dynamically provision nodes via `NodePool` and `AKSNodeClass` CRDs. NAP-provisioned nodes:
- May use custom subnets specified in `AKSNodeClass.vnetSubnetID`
- Are not visible as traditional agent pools in the AKS API
- Only support Azure CNI Overlay, Azure CNI with Cilium, or Azure CNI (flat)
- Do not support Calico network policy or dynamic IP allocation

The extension currently discovers node pools through the AKS Agent Pools API and VMSS/VM enumeration. NAP-provisioned nodes outside traditional agent pools would be missed.

**Impact:** High. NAP adoption is growing. Diagnostics may be incomplete for clusters with NAP-provisioned pools.

### Gap Details: Virtual Nodes (ACI)

Virtual Nodes use Azure Container Instances for serverless pod execution. They require:
- A dedicated subnet delegated to `Microsoft.ContainerInstance/containerGroups`
- Network connectivity between the ACI subnet and cluster subnet
- Specific NSG rules for ACI traffic

The extension does not detect or validate virtual node configurations.

**Impact:** Medium. Virtual Nodes are a specific deployment pattern with moderate adoption.

---

## Connectivity Testing

| Test | Status | Requirements |
|------|--------|-------------|
| MCR DNS resolution | Supported | VMSS or VM RunCommand |
| MCR HTTPS connectivity | Supported | VMSS or VM RunCommand |
| API server DNS resolution | Supported | VMSS or VM RunCommand |
| API server HTTPS connectivity | Supported | VMSS or VM RunCommand |
| Private cluster IP resolution | Supported | Validates private vs public IP for private clusters |
| Stopped cluster detection | Supported | Skips probes for stopped clusters |
| Custom endpoint testing | Gap | Cannot test user-specified endpoints |
| NAP node probe capability | Gap | Cannot run probes on Karpenter-provisioned nodes that lack VMSS RunCommand |
| NTP validation | Gap | No NTP port (123) connectivity test |

---

## Advanced Networking Features

### Advanced Container Networking Services (ACNS)

**Reference:** [ACNS overview](https://learn.microsoft.com/azure/aks/advanced-container-networking-services-overview)

ACNS features (Container Network Observability, Container Network Security, FQDN filtering, L7 policies, WireGuard/mTLS transit encryption, container network logs) operate at the Kubernetes/eBPF layer and are outside the extension's scope. The extension focuses on Azure infrastructure networking: VNets, NSGs, routing, DNS, and outbound connectivity. ACNS does not change any of these infrastructure-level configurations.

### Dual-Stack / IPv6 Networking

**Reference:** [Dual-stack networking in AKS](https://learn.microsoft.com/azure/aks/configure-dual-stack)

| Feature | Status | Notes |
|---------|--------|-------|
| IPv4 address analysis | Supported | All modules handle IPv4 |
| IPv6 address detection | Gap | No IPv6-aware address parsing |
| Dual-stack service validation | Gap | No dual-stack LoadBalancer checks |
| IPv6 NSG rules | Gap | Rules only analyzed for IPv4 |
| IPv6 route analysis | Gap | Routes only analyzed for IPv4 |
| Dual-stack pod CIDR | Gap | Only IPv4 pod CIDR checked |

**Impact:** Medium. Dual-stack requires Azure CNI Overlay and is seeing increasing adoption. IPv6 misconfigurations would not be detected.

### Network Policies

Network policies (Azure NPM, Calico, Cilium) operate at the Kubernetes pod level and are outside the extension's scope. The extension focuses on Azure infrastructure networking: VNets, NSGs, routing, DNS, and outbound connectivity. Network policy enforcement does not affect any of the extension's diagnostic checks.

---

## Platform Changes and Retirements

### Default Outbound Access Retirement (March 31, 2026)

**Reference:** [Azure Updates retirement announcement](https://azure.microsoft.com/updates?id=default-outbound-access-for-vms-in-azure-will-be-retired-transition-to-a-new-method-of-internet-access)

Starting March 31, 2026, AKS no longer supports default outbound access for VMs. New AKS clusters using AKS-managed VNets place cluster subnets into private subnets (`defaultOutboundAccess = false`) by default.

| Check | Status | Notes |
|-------|--------|-------|
| Detection of `defaultOutboundAccess` setting | Gap | Not checked in cluster network profile |
| Warning for clusters relying on default outbound | Gap | No migration guidance |
| Private subnet detection | Gap | No awareness of new default behavior |

**Impact:** Medium. This change is now active (past the March 31, 2026 deadline). Clusters created after this date automatically have `defaultOutboundAccess = false`. The extension should be aware of this when analyzing outbound connectivity. Existing clusters using BYO VNets are unaffected.

### Azure Linux 2.0 Retirement

Azure Linux 2.0 node images are retired as of March 31, 2026. This does not directly affect networking diagnostics but could be relevant for OS-level DNS or networking stack differences.

**Impact:** None for networking diagnostics.

---

## Permission Handling

| Scenario | Status | Extension Behavior |
|----------|--------|-------------------|
| Full permissions | Supported | Complete analysis |
| Missing VNet read | Supported | Graceful degradation + PERMISSION_INSUFFICIENT finding |
| Missing VMSS read | Supported | Graceful degradation + PERMISSION_INSUFFICIENT finding |
| Missing Load Balancer read | Supported | Graceful degradation + PERMISSION_INSUFFICIENT finding |
| Missing all network permissions | Supported | Clear error messages with role assignment guidance |
| Cross-subscription resources | Supported | BYO DNS zones, hub VNet resources |

---

## Output and Reporting

| Format | Status | Notes |
|--------|--------|-------|
| Console summary (default) | Supported | Markdown-formatted findings |
| Console detailed (`--details`) | Supported | Full network config, NSG rules, VNet topology |
| JSON report (`--json-report`) | Supported | Structured data for automation |
| `--output json/yaml/tsv` | Supported | CLI framework integration |
| Finding severity levels (CRITICAL, WARNING, INFO) | Supported | Consistent across all analyzers |
| Actionable remediation guidance | Supported | Role assignments, configuration fixes |

---

## Gap Summary and Prioritization

### High Priority

These gaps affect commonly used or growing AKS features and could produce incorrect or incomplete diagnostics.

| Gap | Feature Category | Impact | Effort Estimate |
|-----|-----------------|--------|-----------------|
| Outbound type `none` | Outbound Analysis | Extension may produce false findings for network isolated clusters | Medium |
| Outbound type `block` (preview) | Outbound Analysis | Extension may produce false findings for network isolated clusters | Medium |
| Network isolated cluster validation | Cluster Access | Missing bootstrap ACR, private endpoint, and egress restriction checks | High |
| Service tags in authorized IP ranges (preview) | API Server Security | Extension may fail to parse or misinterpret service tag entries | Medium |
| Node Auto-Provisioning (NAP) | Node Infrastructure | Karpenter-provisioned nodes are invisible to current discovery | High |
| `defaultOutboundAccess` retirement awareness | Platform Changes | No detection or guidance for the new default behavior (now active) | Low |
| HTTP proxy configuration | Outbound Analysis | May produce false NSG findings; proxy egress path not reported | Medium |

### Medium Priority

These gaps affect less common configurations or emerging features.

| Gap | Feature Category | Impact | Effort Estimate |
|-----|-----------------|--------|-----------------|
| Dual-stack / IPv6 networking | Advanced Networking | IPv6 misconfigurations not detected | High |
| Virtual Nodes (ACI) | Node Infrastructure | ACI networking not validated | Medium |
| AKS LocalDNS (preview) | DNS Analysis | May affect probe test interpretation | Low |
| ~~Cilium-specific dataplane~~ | ~~Network Plugin~~ | ~~Not a gap: Cilium does not affect infrastructure-level checks~~ | N/A |
| NAT Gateway StandardV2 SKU | Outbound Analysis | Informational only, no functional impact | Low |

### Low Priority / Future

These are either informational or affect niche scenarios.

| Gap | Feature Category | Impact | Effort Estimate |
|-----|-----------------|--------|-----------------|
| ACNS (observability, security, encryption) | Out of Scope | Kubernetes/eBPF layer, not applicable to infrastructure diagnostics | N/A |
| Network policy validation (Calico, Azure NPM, Cilium) | Out of Scope | Pod-level policies, not applicable to infrastructure diagnostics | N/A |
| BYO CNI plugin support | Network Plugin | Niche deployment pattern | Low |
| Custom endpoint testing | Connectivity Testing | User-configurable probe targets | Medium |
| NTP connectivity validation | Connectivity Testing | Additional probe test | Low |

---

## References

- [AKS Networking Concepts](https://learn.microsoft.com/azure/aks/concepts-network)
- [AKS CNI Networking Overview](https://learn.microsoft.com/azure/aks/concepts-network-cni-overview)
- [Customize Cluster Egress with Outbound Types](https://learn.microsoft.com/azure/aks/egress-outboundtype)
- [Network Isolated AKS Clusters](https://learn.microsoft.com/azure/aks/concepts-network-isolated)
- [API Server Authorized IP Ranges](https://learn.microsoft.com/azure/aks/api-server-authorized-ip-ranges)
- [Service Tags for API Server Authorized IPs (Preview)](https://learn.microsoft.com/azure/aks/api-server-service-tags)
- [Plan Control Plane Networking](https://learn.microsoft.com/azure/aks/plan-control-plane-networking)
- [Dual-Stack Networking in AKS](https://learn.microsoft.com/azure/aks/configure-dual-stack)
- [Node Auto-Provisioning (NAP) Overview](https://learn.microsoft.com/azure/aks/node-auto-provisioning)
- [NAP Networking Configuration](https://learn.microsoft.com/azure/aks/node-auto-provisioning-networking)
- [Advanced Container Networking Services Overview](https://learn.microsoft.com/azure/aks/advanced-container-networking-services-overview)
- [Azure CNI Powered by Cilium](https://learn.microsoft.com/azure/aks/azure-cni-powered-by-cilium)
- [Outbound Rules and FQDN for AKS](https://learn.microsoft.com/azure/aks/outbound-rules-control-egress)
- [Default Outbound Access Retirement](https://azure.microsoft.com/updates?id=default-outbound-access-for-vms-in-azure-will-be-retired-transition-to-a-new-method-of-internet-access)
- [HTTP Proxy Support in AKS](https://learn.microsoft.com/azure/aks/http-proxy)
