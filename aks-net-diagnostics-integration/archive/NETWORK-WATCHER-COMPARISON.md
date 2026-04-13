# AKS Net-Diagnostics vs Azure Network Watcher - Comparison Analysis

**Created:** December 17, 2025  
**Purpose:** Understand overlap and alignment opportunities between AKS Net-Diagnostics CLI extension and Azure Network Watcher tools

---

## Executive Summary

The feedback suggests aligning the AKS Net-Diagnostics CLI with Azure Network Watcher tools to provide a consistent experience between CLI and Portal. This document analyzes the overlap and identifies opportunities for integration.

### Key Findings

| Aspect | Net-Diagnostics POC | Network Watcher | Alignment Opportunity |
|--------|---------------------|-----------------|----------------------|
| **Focus** | AKS-specific holistic analysis | Generic IaaS network troubleshooting | Complement each other |
| **Scope** | Cluster-wide context | Per-VM/NIC/VMSS analysis | Can integrate NW as backend |
| **UX** | CLI-first, structured reports | Portal-first, CLI via `az network watcher` | Align output formats |
| **Value-Add** | AKS knowledge (MCR, API server, CNI) | Low-level network diagnostics | Use NW tools for primitives |

### 🆕 Important Discovery: AKS-Specific Network Watcher Features

Microsoft has recently added **AKS-specific capabilities** to Network Watcher:

1. **AKS Cluster Topology Visualization (Preview)** - Network Watcher now supports AKS visualization directly
2. **Azure Virtual Network Verifier (Preview)** - Recommended for AKS outbound connectivity troubleshooting
3. **Connectivity Analysis from AKS Nodes** - Portal-based tool accessible from AKS Node Pools blade
4. **Advanced Container Networking Services (ACNS)** - Enterprise-grade network observability for AKS

These represent **significant overlap** with the POC and should be carefully considered for integration.

---

## 🆕 AKS-Specific Network Watcher & Related Tools

### 1. AKS Cluster Topology Visualization (Preview)

**Source:** [Network Watcher Topology - AKS Support](https://learn.microsoft.com/en-us/azure/network-watcher/network-insights-topology#aks-cluster-topology-visualization-preview)

Network Watcher now provides **native AKS topology visualization** in the Azure portal:

| Feature | Description |
|---------|-------------|
| **Resource visualization** | VNets, subnets, NSGs, load balancers, NAT gateways, public IPs |
| **Connectivity insights** | Active connections and connection drops |
| **Traffic metrics** | Bytes forwarded and bytes dropped |
| **Resource health** | State of networking components |

**Supported AKS Scenarios:**
- Default AKS clusters (Kubenet, no custom VNet/UDR)
- Kubenet with custom VNet and UDR
- Azure CNI (with or without custom VNet)
- Managed and user-managed NAT Gateway
- Private clusters and clusters with Azure Firewall
- Node pools in separate subnets
- Dynamic IP allocation for pods

**Overlap with POC:** 🔴 HIGH - This provides visual topology similar to what POC analyzes programmatically.

---

### 2. Azure Virtual Network Verifier (Preview)

**Source:** [Azure Virtual Network Verifier](https://learn.microsoft.com/en-us/azure/virtual-network-manager/concept-virtual-network-verifier)

This is the **recommended tool for AKS outbound connectivity troubleshooting** per Microsoft docs:

| Feature | Description |
|---------|-------------|
| **Reachability analysis** | Check if traffic can reach from source to destination |
| **Path visualization** | Full traffic path with blockers identified |
| **Multi-resource evaluation** | NSG, ASG, admin rules, route tables, peering, firewalls |

**Resources evaluated:**
- Network security group (NSG) rules
- Application security group (ASG) rules
- Azure Virtual Network Manager security admin rules
- Virtual network peering
- Route tables
- Service endpoints & access control lists
- Private endpoints
- Virtual WAN
- Azure Firewall (static L4 only)

**CLI Commands:**
```bash
# Create reachability analysis intent
az network manager verifier-workspace reachability-analysis-intent create \
    --manager-name <network-manager> \
    --workspace-name <workspace> \
    --name <intent-name> \
    --source-resource-id <vmss-instance-id> \
    --dest-resource-id <destination-id> \
    --ip-traffic "..."

# Run reachability analysis
az network manager verifier-workspace reachability-analysis-run create \
    --manager-name <network-manager> \
    --workspace-name <workspace> \
    --name <run-name> \
    --intent-id <intent-id>
```

**Overlap with POC:** 🔴 HIGH - This evaluates NSG, routes, peering - same as POC's static analysis but with flow simulation.

---

### 3. AKS Connectivity Analysis (Portal)

**Source:** [Basic troubleshooting of outbound connections from AKS](https://learn.microsoft.com/en-us/troubleshoot/azure/azure-kubernetes/connectivity/basic-troubleshooting-outbound-connections)

There's a **built-in connectivity analysis tool** in the AKS Portal:

**How to access:**
1. Navigate to AKS cluster in Azure Portal
2. Go to **Settings → Node pools**
3. Select a node pool
4. Click **"Connectivity analysis (Preview)"** in toolbar
5. Select VMSS instance as source
6. Enter destination (e.g., `mcr.microsoft.com`)
7. View path diagram and JSON output

**Overlap with POC:** 🔴 HIGH - This is exactly what `--probe-test` does but in the Portal!

---

### 4. Advanced Container Networking Services (ACNS)

**Source:** [ACNS Network Observability Guide](https://learn.microsoft.com/en-us/azure/aks/container-network-observability-guide)

This is Microsoft's **enterprise-grade network observability platform for AKS**:

| Feature | Description |
|---------|-------------|
| **Container Network Logs** | DNS queries, packet drops, flow logs |
| **Container Network Metrics** | Node-level network metrics |
| **Grafana Dashboards** | Pre-built visualization |
| **L7 Traffic Observability** | HTTP, gRPC, Kafka traffic analysis |

**Use Cases Covered:**
1. DNS issues root cause analysis
2. Packet drops at cluster/pod level
3. Network policy misconfiguration
4. Real-time cluster health monitoring
5. Application-level network issues (L7)

**Overlap with POC:** 🟡 MEDIUM - ACNS is more about runtime observability, POC is about configuration analysis.

---

### 5. AKS Diagnose and Solve Problems

**Source:** [AKS Diagnostics Overview](https://learn.microsoft.com/en-us/azure/aks/aks-diagnostics)

Built-in AKS diagnostic capability in the Portal:

| Category | Diagnostics Available |
|----------|----------------------|
| **Connectivity Issues** | DNS, VNet configuration, API server connectivity |
| **Network Configuration** | NSG rules, route tables, subnet configuration |
| **Cluster Health** | Node status, control plane health |

**Overlap with POC:** 🟡 MEDIUM - Similar scope but Portal-only, no CLI equivalent.

---

## Revised Overlap Assessment

Given the new AKS-specific features, here's the updated overlap matrix:

| POC Feature | Network Watcher/Azure Tool | Overlap | Recommendation |
|-------------|---------------------------|---------|----------------|
| NSG Analysis | NSG Diagnostics + Virtual Network Verifier | 🔴 HIGH | Use NW APIs |
| Route Analysis | Next Hop + Virtual Network Verifier | 🔴 HIGH | Use NW APIs |
| Connectivity Testing | Connection Troubleshoot + AKS Connectivity Analysis | 🔴 HIGH | **Use existing tools** |
| Topology/Resource View | AKS Topology Visualization | 🔴 HIGH | **Leverage existing** |
| DNS Analysis | ACNS Container Network Logs | 🟡 MEDIUM | Complement ACNS |
| Private DNS | Limited coverage in NW | 🟢 LOW | **POC unique value** |
| AKS-Specific Knowledge | None | 🟢 LOW | **POC unique value** |
| Holistic Report | None | 🟢 LOW | **POC unique value** |

---

## Azure Network Watcher Tools Overview

Network Watcher provides **7 diagnostic tools** for generic Azure IaaS networking:

### 1. IP Flow Verify
**What it does:** Checks if a packet is allowed/denied to/from a VM based on NSG and Azure Virtual Network Manager rules.

| Feature | Network Watcher | Net-Diagnostics POC | Notes |
|---------|-----------------|---------------------|-------|
| Traffic direction test | ✅ TCP/UDP | ❌ Not implemented | NW tests specific flows |
| NSG rule identification | ✅ Per-packet | ✅ Static analysis | Different approaches |
| VMSS support | ❌ VMs only | ✅ VMSS + VMs | POC has advantage |
| AKS context | ❌ None | ✅ AKS-specific rules | POC understands AKS |

**Overlap:** Low - IP Flow Verify is point-in-time per-packet; POC does static rule analysis.

---

### 2. NSG Diagnostics
**What it does:** Simulates traffic flows to determine if allowed/denied at VM, VMSS, or Application Gateway level.

| Feature | Network Watcher | Net-Diagnostics POC | Notes |
|---------|-----------------|---------------------|-------|
| Supported targets | VMs, VMSS NICs, App GW v2 | VMSS node pools | NW broader |
| Flow simulation | ✅ Active simulation | ❌ Static analysis | Different approach |
| Service tag support | ✅ Full | ✅ Full | Equivalent |
| Rule recommendation | ✅ Can add rules | ❌ Read-only | NW can remediate |
| AKS required rules | ❌ Generic | ✅ MCR, API server, inter-node | POC knows AKS |

**Overlap:** MEDIUM - Both analyze NSGs, but approaches differ significantly.

**Integration Opportunity:** Could invoke NSG Diagnostics API for specific flow tests instead of static analysis.

---

### 3. Next Hop
**What it does:** Determines where traffic is routed (next hop type, IP, route table).

| Feature | Network Watcher | Net-Diagnostics POC | Notes |
|---------|-----------------|---------------------|-------|
| Next hop detection | ✅ Active lookup | ✅ Route table analysis | Both work |
| Route table ID | ✅ Returned | ✅ Analyzed | Equivalent |
| System routes | ✅ Identified | ✅ Identified | Equivalent |
| UDR detection | ✅ Per-destination | ✅ Full table scan | POC more comprehensive |
| AKS conflicts | ❌ Generic | ✅ API server + authorized IPs | POC knows AKS |

**Overlap:** MEDIUM - Both analyze routing, NW is per-destination, POC is holistic.

**Integration Opportunity:** Could use Next Hop API to validate specific critical paths (e.g., to API server).

---

### 4. Effective Security Rules
**What it does:** Shows aggregated NSG rules applied to a network interface.

| Feature | Network Watcher | Net-Diagnostics POC | Notes |
|---------|-----------------|---------------------|-------|
| Rule aggregation | ✅ Per-NIC | ✅ Per-subnet | Similar |
| Azure Virtual Network Manager | ✅ Included | ❌ Not implemented | Gap in POC |
| CSV export | ✅ Native | ❌ JSON only | NW has better export |
| Priority analysis | ✅ Visual | ✅ Programmatic | Both work |

**Overlap:** HIGH - Both show effective NSG rules, but NW has better per-NIC view.

**Integration Opportunity:** Could use Effective Security Rules API to get exact NIC-level rules.

---

### 5. Connection Troubleshoot
**What it does:** Tests TCP/ICMP connectivity from source to destination with hop-by-hop analysis.

| Feature | Network Watcher | Net-Diagnostics POC | Notes |
|---------|-----------------|---------------------|-------|
| Supported sources | VMs, VMSS, Bastion, App GW | VMSS (via run-command) | NW more robust |
| Supported destinations | VMs, FQDNs, URIs, IPs | MCR, API server only | NW more flexible |
| Latency measurement | ✅ Min/Max/Avg | ❌ Binary pass/fail | NW better |
| Hop-by-hop analysis | ✅ Full path | ❌ Not implemented | NW better |
| Agentless mode | ✅ Preview | ❌ Requires run-command | NW better |
| Issue detection | ✅ CPU, Memory, Firewall, DNS, NSG, UDR | ✅ DNS, NSG, UDR | NW broader |
| AKS endpoints | ❌ Generic | ✅ MCR, API server | POC knows AKS |

**Overlap:** HIGH - This is the closest match to `--probe-test` functionality.

**Integration Opportunity:** **Strong candidate for replacement** - Use Connection Troubleshoot API instead of `run-command` for connectivity tests.

---

### 6. Packet Capture
**What it does:** Creates packet capture sessions for traffic analysis.

| Feature | Network Watcher | Net-Diagnostics POC | Notes |
|---------|-----------------|---------------------|-------|
| Packet capture | ✅ Full capability | ❌ Not implemented | Not in scope |

**Overlap:** None - Packet capture is deep debugging, not in POC scope.

---

### 7. VPN Troubleshoot
**What it does:** Diagnoses VPN gateway and connection issues.

| Feature | Network Watcher | Net-Diagnostics POC | Notes |
|---------|-----------------|---------------------|-------|
| VPN diagnostics | ✅ Full capability | ❌ Not implemented | Not in scope |

**Overlap:** None - VPN troubleshooting not in AKS net-diagnostics scope.

---

## Feature Comparison Matrix

| Diagnostic Category | Network Watcher Tool | Net-Diagnostics POC | Overlap | Integration Path |
|--------------------|---------------------|---------------------|---------|-----------------|
| **NSG Analysis** | NSG Diagnostics + Effective Rules + IP Flow | Static NSG rule analysis | 🟡 MEDIUM | Use NW APIs for specific flow tests |
| **Routing Analysis** | Next Hop | Route table analysis | 🟡 MEDIUM | Use NW API for specific paths |
| **Connectivity Testing** | Connection Troubleshoot | `--probe-test` with run-command | 🔴 HIGH | **Replace run-command with NW API** |
| **DNS Analysis** | Connection Troubleshoot (DNS resolution) | DNS configuration analysis | 🟢 LOW | POC is more AKS-focused |
| **Private DNS** | ❌ Limited | ✅ Full analysis | 🟢 LOW | POC unique value |
| **Private Link** | ❌ Limited | ✅ Full analysis | 🟢 LOW | POC unique value |
| **Cluster Context** | ❌ None | ✅ Full AKS awareness | 🟢 LOW | POC unique value |
| **Topology View** | ✅ Network topology | ❌ Not implemented | 🟢 LOW | Could integrate |

---

## Unique Value of AKS Net-Diagnostics POC

Features that Network Watcher **does NOT provide** and represent unique POC value:

### 1. AKS-Specific Knowledge
- Required MCR connectivity (mcr.microsoft.com, *.data.mcr.microsoft.com)
- API server access patterns and authorized IP conflicts
- Inter-node communication requirements (port 10250, etc.)
- Azure CNI overlay pod CIDR validation
- Network plugin detection and mode (overlay, pod subnet, node subnet)

### 2. Cluster-Wide Holistic Analysis
- Outbound type detection and implications (LoadBalancer, UDR, NAT Gateway)
- Private cluster configuration (BYO DNS, VNet Integration)
- Node pool enumeration and configuration display
- Cross-resource analysis (VNet + NSG + Route Table + DNS as one picture)

### 3. AKS Private Cluster Features
- Private DNS zone validation and VNet link analysis
- API Server VNet Integration detection
- BYO Private DNS Zone (including cross-subscription)

### 4. Structured Diagnostic Output
- Severity-based findings (INFO, WARNING, ERROR, CRITICAL)
- Actionable remediation guidance specific to AKS
- Comprehensive JSON export for automation

---

## Recommended Integration Strategy

### Phase 1: Replace `--probe-test` with Connection Troubleshoot API

**Current Implementation:**
```
POC uses VMSS run-command to execute DNS/HTTPS tests from nodes
```

**Recommended Change:**
```
Use Network Watcher Connection Troubleshoot API:
- az network watcher test-connectivity (CLI)
- Network.ConnectionMonitors / NetworkWatcher.ConnectivityCheck (API)
```

**Benefits:**
- No VMSS run-command permissions required
- Agentless support (preview) - no extension needed
- Hop-by-hop analysis with latency metrics
- Better error classification (CPU, Memory, GuestFirewall, DNS, NSG, UDR)
- Consistent with Portal experience

**CLI Example:**
```bash
az network watcher test-connectivity \
    --source-resource <vmss-instance-id> \
    --dest-address mcr.microsoft.com \
    --dest-port 443 \
    --protocol TCP
```

### Phase 2: Enhance NSG Analysis with NSG Diagnostics API

**Current Implementation:**
```
Static analysis of NSG rules looking for required ports/service tags
```

**Recommended Enhancement:**
```
Use NSG Diagnostics API to simulate specific critical flows:
- mcr.microsoft.com:443 (MCR)
- <api-server-fqdn>:443 (API Server)
- Inter-node communication on port 10250
```

**Benefits:**
- Actual flow simulation rather than static analysis
- Includes Azure Virtual Network Manager admin rules
- Can test ICMP (not supported in IP Flow Verify)

### Phase 3: Add Network Topology Integration

**Opportunity:**
```
Use Network Watcher topology API to provide visual network map
```

**CLI Example:**
```bash
az network watcher show-topology --resource-group <rg> --vnet <vnet>
```

---

## Output Format Alignment

To align CLI experience with Portal, consider these output enhancements:

### Current POC Output (Table Format)
```
=== AKS Network Diagnostics Report ===
Cluster: my-cluster
...
[ERROR] NSG rule blocking outbound HTTPS...
```

### Suggested Aligned Output (Portal-like)
```
┌────────────────────────────────────────────────────────────────┐
│ AKS Network Diagnostics Report                                  │
├────────────────────────────────────────────────────────────────┤
│ Cluster: my-cluster    Status: ⚠ Issues Found                  │
├────────────────────────────────────────────────────────────────┤
│ ▶ NSG Diagnostics                                              │
│   ├─ Rule: DenyAllOutbound (Priority: 4096)                    │
│   │  Status: ❌ Blocking                                       │
│   │  Impact: Blocks MCR connectivity                           │
│   │  Action: Add allow rule for ServiceTag:AzureCloud          │
│   │                                                            │
│ ▶ Connectivity Tests (via Network Watcher)                     │
│   ├─ mcr.microsoft.com:443                                     │
│   │  Status: ✅ Reachable                                      │
│   │  Latency: 12ms (avg)                                       │
│   │                                                            │
│ ▶ Route Analysis                                               │
│   ├─ Next Hop to API Server                                    │
│   │  Type: VirtualAppliance                                    │
│   │  IP: 10.0.0.4 (Azure Firewall)                             │
└────────────────────────────────────────────────────────────────┘
```

---

## API Integration Reference

### Network Watcher REST APIs

| Tool | REST API | Azure CLI Command |
|------|----------|-------------------|
| Connection Troubleshoot | `POST /networkWatchers/{nw}/connectivityCheck` | `az network watcher test-connectivity` |
| NSG Diagnostics | `POST /networkWatchers/{nw}/networkConfigurationDiagnostic` | `az network watcher run-configuration-diagnostic` |
| Next Hop | `POST /networkWatchers/{nw}/nextHop` | `az network watcher show-next-hop` |
| IP Flow Verify | `POST /networkWatchers/{nw}/ipFlowVerify` | `az network watcher test-ip-flow` |
| Effective Security Rules | `GET /networkInterfaces/{nic}/effectiveNetworkSecurityGroups` | `az network nic list-effective-nsg` |

### Python SDK Integration

```python
from azure.mgmt.network import NetworkManagementClient

# Connection Troubleshoot
connectivity_parameters = {
    'source': {'resource_id': vmss_instance_id},
    'destination': {'address': 'mcr.microsoft.com', 'port': 443},
    'protocol': 'TCP'
}
result = network_client.network_watchers.begin_check_connectivity(
    resource_group_name='NetworkWatcherRG',
    network_watcher_name='NetworkWatcher_eastus',
    parameters=connectivity_parameters
).result()

# NSG Diagnostics
diagnostic_parameters = {
    'target_resource_id': vmss_nic_id,
    'profiles': [{
        'direction': 'Outbound',
        'protocol': 'TCP',
        'source': '10.0.0.4',
        'destination': 'mcr.microsoft.com',
        'destination_port': '443'
    }]
}
result = network_client.network_watchers.begin_get_network_configuration_diagnostic(
    resource_group_name='NetworkWatcherRG',
    network_watcher_name='NetworkWatcher_eastus',
    parameters=diagnostic_parameters
).result()
```

---

## Summary: Recommended Path Forward

### Keep in POC (Unique Value)
1. ✅ AKS-specific knowledge and required endpoints
2. ✅ Cluster configuration analysis (outbound type, network plugin, private cluster)
3. ✅ Private DNS zone and VNet link analysis
4. ✅ Holistic cross-resource view
5. ✅ Structured diagnostic report with AKS remediation guidance

### Integrate from Network Watcher
1. 🔄 **Connection Troubleshoot** - Replace `--probe-test` implementation
2. 🔄 **NSG Diagnostics** - Enhance NSG analysis with flow simulation
3. 🔄 **Next Hop** - Validate specific routing paths
4. 🔄 **Effective Security Rules** - Get precise per-NIC rules

### Align with Portal
1. 📊 Match output structure with Portal diagnostic results
2. 📊 Use same severity levels and categorization
3. 📊 Provide links to Portal for deeper investigation

---

## Next Steps

1. **Discuss with Network Watcher team** about AKS-specific integration requirements
2. **Prototype Connection Troubleshoot integration** to replace run-command
3. **Evaluate permission model** - Network Watcher requires different RBAC
4. **Design unified output format** that works for both CLI and Portal

---

## References

- [Azure Network Watcher Overview](https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview)
- [NSG Diagnostics Overview](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-diagnostics-overview)
- [Connection Troubleshoot Overview](https://learn.microsoft.com/en-us/azure/network-watcher/connection-troubleshoot-overview)
- [Next Hop Overview](https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-next-hop-overview)
- [IP Flow Verify Overview](https://learn.microsoft.com/en-us/azure/network-watcher/ip-flow-verify-overview)
- [Effective Security Rules Overview](https://learn.microsoft.com/en-us/azure/network-watcher/effective-security-rules-overview)
