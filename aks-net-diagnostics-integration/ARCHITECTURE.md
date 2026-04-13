# AKS Net-Diagnostics Extension: Architecture

## Table of Contents

1. [Overview](#overview)
2. [POC Evolution](#poc-evolution)
3. [Architecture Overview](#architecture-overview)
4. [Extension Structure](#extension-structure)
5. [Integration Design](#integration-design)
6. [Module Breakdown](#module-breakdown)
7. [Data Flow](#data-flow)
8. [Authentication Architecture](#authentication-architecture)
9. [Design Decisions](#design-decisions)
10. [Code Quality](#code-quality)
11. [Testing Status](#testing-status)

## Overview

`aks-net-diagnostics` is an Azure CLI **extension** that provides comprehensive, read-only network diagnostics for AKS clusters. It is installed and updated independently of Azure CLI through `az extension add / az extension update`.

**Command:** `az aks net-diagnostics`

The diagnostic engine analyzes cluster networking configuration across multiple dimensions, including DNS, outbound connectivity, NSGs, routing, private DNS, and API server access. It correlates findings to surface misconfigurations with actionable remediation guidance.

## POC Evolution

This extension is the latest stage in an iterative proof-of-concept:

| Stage | Form Factor | Key Milestone |
|-------|-------------|---------------|
| 1 | Standalone Python script | Validated diagnostic concepts |
| 2 | Azure SDK integration (`aks-net-diagnostics` repo) | Proper Azure API patterns, `DefaultAzureCredential` |
| 3 | Azure CLI fork (subcommand under `az aks`) | CLI-native auth, 4 modified files in `acs` module |
| 4 | **Azure CLI extension** (current) | Self-contained package, independent release cycle |

### Why the Move to an Extension

Stage 3 embedded the diagnostic engine inside the `acs` command module of an `azure-cli` fork, requiring modifications to 4 existing files (`commands.py`, `_params.py`, `custom.py`, `_client_factory.py`). This worked for validation but had drawbacks:

- Tightly coupled to the azure-cli release cycle
- Required maintaining a fork with merge conflicts on every upstream sync
- Changes to existing files increased review and merge risk

The extension model (Stage 4) eliminates all of these: the diagnostic engine lives in its own package under `azure-cli-extensions`, modifies zero existing files, and can be versioned, tested, and released independently.

## Architecture Overview

### Design Philosophy

**Core Principles:**

1. **Read-Only Operation.** No Azure resources are created, modified, or deleted.
2. **CLI-Native Authentication.** Uses Azure CLI's credential system via `get_mgmt_service_client()`.
3. **Self-Contained Extension.** Zero modifications to Azure CLI core or other extensions.
4. **Graceful Degradation.** Missing permissions produce findings, not failures.
5. **Minimal Dependencies.** Only declares `azure-mgmt-network~=25.0` (not bundled with CLI 2.83+). All other SDK packages are bundled with the CLI itself.

### High-Level Architecture

```mermaid
flowchart TD
    CMD["az aks net-diagnostics -n cluster -g rg<br/>--details / --probe-test / --json-report"]

    subgraph EXT[" "]
        direction TB
        ADAPTER["CLI Adapter Layer<br/>__init__.py, commands.py, _params.py,<br/>_client_factory.py, custom.py"]
        ADAPTER --> ORCH["Orchestrator<br/>10-phase sequential workflow"]
        ORCH --> ANALYZERS["Analyzers<br/>NSG, DNS, Routes, Outbound,<br/>API Server, Connectivity, Misconfiguration"]
        ANALYZERS --> REPORT["Report Generator<br/>Console + JSON output"]
    end

    CS["ContainerService<br/>AKS + AgentPools"]
    NET["Network<br/>VNets, NSGs, Routes, LBs, NatGW"]
    CMP["Compute<br/>VMSS, VMs, RunCommand"]
    PDNS["PrivateDNS<br/>Zones, VNet links"]

    CMD --> ADAPTER
    ANALYZERS --> CS & NET & CMP & PDNS
```

## Extension Structure

```
src/aks-net-diagnostics/
├── setup.py                              # Package configuration, dependencies
├── README.md                             # Extension documentation
├── HISTORY.rst                           # Release history
├── azext_aks_net_diagnostics/
│   ├── __init__.py                       # AzCommandsLoader (extension entry point)
│   ├── _version.py                       # Version string
│   ├── _help.py                          # Help text definitions
│   ├── _params.py                        # CLI parameter definitions
│   ├── _client_factory.py                # Azure SDK client factories (5 clients)
│   ├── commands.py                       # Command registration
│   ├── custom.py                         # Command handler (bridge to engine)
│   ├── azext_metadata.json               # Extension metadata
│   │
│   │── # Diagnostic Engine ──────────────
│   ├── orchestrator.py                   # 10-phase diagnostic coordinator
│   ├── cluster_data_collector.py         # Azure data gathering (AKS, VMSS, VMs)
│   ├── nsg_analyzer.py                   # NSG rule validation
│   ├── dns_analyzer.py                   # DNS / private DNS configuration
│   ├── route_table_analyzer.py           # UDR impact analysis
│   ├── api_server_analyzer.py            # API server access security
│   ├── outbound_analyzer.py              # Outbound config (LB, NAT GW, UDR)
│   ├── connectivity_tester.py            # Active probe tests via RunCommand (VMSS + VM)
│   ├── misconfiguration_analyzer.py      # Cross-component correlation
│   ├── report_generator.py              # Console + JSON report output
│   │
│   │── # Shared ─────────────────────────
│   ├── base_analyzer.py                  # Abstract base for analyzers
│   ├── models.py                         # Finding, FindingCode, Severity, etc.
│   ├── exceptions.py                     # Custom exception hierarchy
│   ├── validators.py                     # Input validation and sanitization
│   │
│   └── tests/                            # Test scaffolding
│       ├── __init__.py
│       └── latest/
│           ├── __init__.py
│           └── test_aks_net_diagnostics.py
```

**Total: 21 Python modules**

## Integration Design

### Extension Entry Point (`__init__.py`)

Azure CLI discovers extensions through a `COMMAND_LOADER_CLS` class:

```python
class AksNetDiagnosticsCommandsLoader(AzCommandsLoader):
    def load_command_table(self, args):
        from azext_aks_net_diagnostics.commands import load_command_table
        load_command_table(self, args)
        return self.command_table

    def load_arguments(self, command):
        from azext_aks_net_diagnostics._params import load_arguments
        load_arguments(self, command)

COMMAND_LOADER_CLS = AksNetDiagnosticsCommandsLoader
```

### Command Registration (`commands.py`)

```python
with self.command_group('aks net-diagnostics', managed_clusters_sdk,
                        client_factory=cf_managed_clusters) as g:
    g.custom_command('', 'aks_net_diagnostics')
```

Registers `az aks net-diagnostics` as a custom command group with an empty subcommand name, so the command group itself is the executable command.

### Parameter Definitions (`_params.py`)

| Parameter | Short | Type | Description |
|-----------|-------|------|-------------|
| `--resource-group` | `-g` | string | Resource group name |
| `--name` | `-n` | string | AKS cluster name |
| `--details` | | flag | Show detailed diagnostic output |
| `--probe-test` | | flag | Run active connectivity tests from nodes |
| `--json-report` | | string | Path to write JSON report |

### Client Factories (`_client_factory.py`)

Five client factories create pre-authenticated SDK clients using `get_mgmt_service_client()`:

| Factory | SDK Client | Purpose |
|---------|-----------|---------|
| `cf_managed_clusters` | `ContainerServiceClient.managed_clusters` | Cluster info |
| `cf_agent_pools` | `ContainerServiceClient.agent_pools` | Agent pool details |
| `cf_network_client` | `NetworkManagementClient` | VNets, NSGs, routes, LBs, NAT GWs |
| `cf_compute_client` | `ComputeManagementClient` | VMSS, VMs, RunCommand |
| `cf_privatedns_client` | `PrivateDnsManagementClient` | Private DNS zones, VNet links |

All factories accept an optional `subscription_id` parameter for cross-subscription resource access.

### Command Handler (`custom.py`)

Bridges the Azure CLI framework to the diagnostic engine:

```python
def aks_net_diagnostics(cmd, client, resource_group_name, name,
                        details=False, probe_test=False, json_report=None):
    # Get subscription + credential from CLI context
    profile = Profile(cli_ctx=cmd.cli_ctx)
    subscription_id = profile.get_subscription_id()
    credential = profile.get_login_credentials()[0]

    # Create all required clients
    aks_client = client
    agent_pools_client = cf_agent_pools(cmd.cli_ctx)
    network_client = cf_network_client(cmd.cli_ctx)
    compute_client = cf_compute_client(cmd.cli_ctx)
    privatedns_client = cf_privatedns_client(cmd.cli_ctx)

    # Detect output format (suppress console for --output json/yaml/tsv)
    output_format = cmd.cli_ctx.invocation.data.get('output', 'table')
    suppress_console = output_format != 'table'

    # Delegate to orchestrator
    result = run_diagnostics(
        aks_client=aks_client, agent_pools_client=agent_pools_client,
        network_client=network_client, compute_client=compute_client,
        privatedns_client=privatedns_client, credential=credential,
        resource_group_name=resource_group_name, cluster_name=name,
        subscription_id=subscription_id, details=details,
        probe_test=probe_test, json_report_path=json_report,
        logger=logger, suppress_console_output=suppress_console
    )
    return result
```

## Module Breakdown

### Orchestrator (`orchestrator.py`)

Coordinates the 10-phase diagnostic workflow. Accepts pre-authenticated clients and parameters and returns a structured result dictionary.

**`run_diagnostics()` signature:**

```python
def run_diagnostics(
    aks_client, agent_pools_client, network_client, compute_client,
    privatedns_client, credential, resource_group_name, cluster_name,
    subscription_id, details=False, probe_test=False,
    json_report_path=None, logger=None, suppress_console_output=False
) -> Dict[str, Any]:
```

**10-Phase Flow:**

| Phase | Step | Module | Description |
|-------|------|--------|-------------|
| 1 | `[1/8]` | `ClusterDataCollector` | Cluster info + agent pools |
| 2 | `[2/8]` | `ClusterDataCollector` | VMSS/VM collection, VNet analysis, subnet enrichment |
| 3 | `[3/8]` | `RouteTableAnalyzer` | UDR impact on traffic flow |
| 4 | `[4/8]` | `OutboundConnectivityAnalyzer` | Outbound type, LB/NAT GW IPs |
| 5 | `[5/8]` | `NSGAnalyzer` | NSG rules, blocking detection |
| 6 | `[6/8]` | `DNSAnalyzer` | DNS servers, private DNS zones, VNet links |
| 7 | `[7/8]` | `APIServerAccessAnalyzer` | Authorized IP ranges, private endpoint |
| 8 | `[8/8]` | `ConnectivityTester` | Active DNS + HTTPS probes (optional) |
| 9 | | `MisconfigurationAnalyzer` | Cross-component correlation |
| 10 | | `ReportGenerator` | Console + JSON output |

Between phases the orchestrator enriches agent pool data with subnet CIDRs from actual VMSS/VM NICs (helper functions `_enrich_agent_pools_with_vmss_subnets`, `_enrich_agent_pools_with_vm_subnets`), runs NAP analysis for Karpenter VM detection (`_analyze_nap`, `_classify_nap_vms`, `_classify_nap_vmss`), and collects/deduplicates permission findings from all analyzers.

### ClusterDataCollector (`cluster_data_collector.py`)

Centralized Azure data gathering. Accepts individual SDK clients (AKS, AgentPools, Network, Compute).

**Key Methods:**

| Method | Data Source | Returns |
|--------|-----------|--------|
| `collect_cluster_info()` | AKS API | Cluster config, network profile, agent pools, NAP detection |
| `collect_vnet_info()` | Network API | VNet topology, subnets, peerings, `defaultOutboundAccess` |
| `collect_vmss_info()` | Compute API | VMSS network profiles, instances |
| `collect_vm_info()` | Compute API | VM NICs (for VirtualMachines node pools and NAP/Karpenter VMs) |

Handles authorization errors gracefully by storing permission findings rather than raising exceptions, so downstream analyzers can still run on available data.

### NSGAnalyzer (`nsg_analyzer.py`)

Inherits `BaseAnalyzer`. Validates NSGs attached to subnets and NICs used by the cluster.

**Analyzes:**
- Required AKS outbound rules (MCR, AzureCloud, DNS) with adapted rule sets for network-isolated clusters
- HTTP proxy NSG compliance (`AKS_HTTP_Proxy` rule, proxy traffic blocking detection)
- Inter-node communication rules
- Blocking rules and override detection
- Service tag semantics
- Azure CNI Overlay pod CIDR traffic rules

**Key Finding Codes:** `NSG_INTER_NODE_BLOCKED`, `NSG_BLOCKING_AKS_TRAFFIC`, `NSG_POTENTIAL_BLOCK`, `NSG_POD_CIDR_BLOCKED`, `NSG_POD_CIDR_PARTIAL`

### DNSAnalyzer (`dns_analyzer.py`)

Inherits `BaseAnalyzer`. Validates DNS configuration and private DNS zone linkage.

**Analyzes:**
- Azure default DNS vs custom DNS servers
- Private DNS zone configuration
- VNet links for private clusters (including cross-subscription BYO DNS zones)
- DNS server VNet hosting and reachability

**Key Finding Codes:** `PRIVATE_DNS_MISCONFIGURED`, `DNS_RESOLUTION_FAILED`

### RouteTableAnalyzer (`route_table_analyzer.py`)

Evaluates User Defined Routes associated with cluster subnets.

**Analyzes:**
- Default route (0.0.0.0/0) presence and next-hop type
- Routes to `VirtualAppliance` (firewall/NVA) or `VirtualNetworkGateway`
- Impact on AKS management and outbound traffic

**Key Finding Codes:** `UDR_CONFLICT`

### OutboundConnectivityAnalyzer (`outbound_analyzer.py`)

Determines effective outbound configuration and public IPs.

**Analyzes:**
- Outbound type: `loadBalancer`, `managedNATGateway`, `userAssignedNATGateway`, `userDefinedRouting`, `none`, `block`
- Load balancer frontend IPs and outbound rules
- NAT Gateway resources and public IPs (managed and user-assigned)
- UDR impact on outbound traffic path
- Network-isolated clusters (`none`/`block`): bootstrap ACR validation
- HTTP proxy: detection, VNet reachability via peering, proxy IP/port extraction
- `defaultOutboundAccess` subnet awareness

**Key Finding Codes:** `OUTBOUND_TYPE_NONE`, `OUTBOUND_TYPE_BLOCK`, `BOOTSTRAP_ACR_MISSING`, `HTTP_PROXY_CONFIGURED`, `PROXY_NOT_REACHABLE`, `DEFAULT_OUTBOUND_ACCESS_DISABLED`, `PERMISSION_INSUFFICIENT_LB`

### APIServerAccessAnalyzer (`api_server_analyzer.py`)

Validates API server network access configuration.

**Analyzes:**
- Public vs private cluster setup
- VNet integration detection
- Authorized IP ranges (CIDRs and service tags), validating cluster outbound IPs are included
- Service tag detection, multiple-tag warnings, VNet Integration compatibility
- UDR override detection, since a firewall or NVA may change the source IP

**Key Finding Codes:** `API_ACCESS_RESTRICTED`, `SERVICE_TAG_IN_AUTH_RANGES`, `SERVICE_TAG_VNET_INTEGRATION_CONFLICT`

### ConnectivityTester (`connectivity_tester.py`)

Active probe testing using RunCommand on VMSS and VM node pools. Only runs when `--probe-test` is specified.

**Tests:**
- MCR DNS resolution and HTTPS connectivity (standard clusters)
- Bootstrap ACR DNS and HTTPS connectivity (network-isolated `none`/`block` clusters)
- API server DNS resolution and HTTPS connectivity (all clusters)
- HTTP proxy connectivity (proxy-configured clusters)

**Features:**
- Dependency-aware execution (skips HTTPS test if DNS fails)
- Supports both VMSS and standalone VM node pools (VirtualMachines type)
- RunCommand execution with configurable timeouts
- Permission detection for RunCommand failures

**Key Finding Codes:** `PERMISSION_INSUFFICIENT_VMSS`

### MisconfigurationAnalyzer (`misconfiguration_analyzer.py`)

Cross-component correlation engine. Receives results from all other analyzers and detects composite issues.

**Analyzes:**
- Cluster provisioning failures and cluster stopped state
- Node pool provisioning failures
- Bootstrap ACR private DNS (`privatelink.azurecr.io`) VNet link validation
- Connectivity test result correlation
- NSG compliance
- DNS misconfiguration patterns (system-managed, BYO, cross-subscription)
- Permission context (prevents false positives when data is incomplete)

**Key Finding Codes:** `CLUSTER_OPERATION_FAILURE`, `CLUSTER_STOPPED`, `BOOTSTRAP_ACR_DNS_NOT_LINKED`, `PRIVATE_DNS_MISCONFIGURED`

### ReportGenerator (`report_generator.py`)

Formats and outputs diagnostic results.

**Output Modes:**
- **Console summary** (default): markdown-formatted overview with findings
- **Console detailed** (`--details`): full network config, NSG rules, VNet topology
- **JSON export** (`--json-report`): structured data for automation
- **Structured output** (`--output json/yaml/tsv`): suppresses console, returns result dict to CLI framework

**Features:**
- Finding severity levels: CRITICAL, WARNING, INFO
- Network topology visualization
- NSG rule formatting
- Permission limitations section
- Subnet CIDR display for all node pool types

### Shared Modules

#### BaseAnalyzer (`base_analyzer.py`)

Abstract base class for `DNSAnalyzer` and `NSGAnalyzer`. Provides:
- Common `__init__` accepting `clients` dict and `cluster_info`
- `add_finding()` method with severity-aware logging
- `get_cluster_property()` for safe nested dict traversal

#### Models (`models.py`)

Data models and constants:
- `Severity` enum: CRITICAL, HIGH, WARNING, INFO
- `FindingCode` enum: 27 standardized finding codes
- `Finding` dataclass: severity, code, message, recommendation, details
- `VMSSInstance` dataclass: VMSS instance metadata for probe testing
- `DiagnosticResult` dataclass: container for all diagnostic output

#### Exceptions (`exceptions.py`)

Custom exception hierarchy rooted in `AKSDiagnosticsError`:
- `AzureSDKError`: API call failures (with error_code, status_code)
- `AzureAuthenticationError`: credential failures
- `ClusterNotFoundError`: cluster not found
- `InvalidConfigurationError`: invalid cluster config
- `ValidationError`: input validation failures

#### InputValidator (`validators.py`)

Input validation and sanitization:
- Cluster name / resource group name pattern matching
- Subscription ID (GUID format) validation
- Output file path validation (directory traversal prevention)

## Data Flow

### Phase Execution and Data Dependencies

```mermaid
flowchart TD
    CUSTOM["custom.py"] --> PROFILE["Profile: subscription_id, credential"]
    CUSTOM --> CLIENTS["Client factories: aks, agent_pools,<br/>network, compute, privatedns"]
    PROFILE --> RD["orchestrator.run_diagnostics(...)"]
    CLIENTS --> RD

    RD --> P1["Phase 1: ClusterDataCollector.collect_cluster_info()<br/>produces: cluster_info, agent_pools"]
    P1 --> P2["Phase 2: collect_vmss_info() + collect_vm_info()<br/>produces: vmss_analysis, vm_analysis<br/>then enrich agent_pools with subnet CIDRs<br/>then collect_vnet_info() → vnets_analysis"]
    P2 --> P3["Phase 3: RouteTableAnalyzer.analyze()<br/>inputs: agent_pools, vmss_analysis, network_client<br/>produces: route_table_analysis"]
    P3 --> P4["Phase 4: OutboundConnectivityAnalyzer.analyze()<br/>inputs: cluster_info, agent_pools, clients,<br/>route_table_analysis, vmss_analysis<br/>produces: outbound_analysis, outbound_ips"]
    P4 --> P5["Phase 5: NSGAnalyzer.analyze()<br/>inputs: clients, cluster_info, vmss_analysis, vm_analysis<br/>produces: nsg_analysis"]
    P5 --> P6["Phase 6: DNSAnalyzer.analyze()<br/>inputs: clients, cluster_info<br/>produces: private_dns_analysis"]
    P6 --> P7["Phase 7: APIServerAccessAnalyzer.analyze()<br/>inputs: cluster_info, outbound_ips, outbound_analysis<br/>produces: api_server_access_analysis"]
    P7 --> P8["Phase 8: ConnectivityTester.test_connectivity()<br/>only if --probe-test<br/>inputs: cluster_info, clients, dns_analyzer<br/>produces: api_probe_results"]
    P8 --> P9["Phase 9: MisconfigurationAnalyzer.analyze()<br/>inputs: all above results + permission_findings<br/>produces: findings[]"]
    P9 --> P10["Phase 10: ReportGenerator<br/>inputs: all results + findings<br/>produces: console output, JSON file, result dict"]
```

### Permission Error Flow

```mermaid
flowchart TD
    ERR["SDK call fails with AuthorizationFailed"] --> CATCH["Analyzer/Collector catches HttpResponseError"]
    CATCH --> FINDING["Creates Finding with PERMISSION_INSUFFICIENT_* code"]
    FINDING --> DEGRADE["Returns None or empty data<br/>allowing graceful degradation"]
    DEGRADE --> DETECT["Orchestrator detects has_vmss_permission_issues"]
    DETECT --> MARK["Marks subsequent analysis as potentially incomplete"]
    DETECT --> HANDLE["Downstream analyzers handle missing data"]
    MARK --> COLLECT["_collect_permission_findings()<br/>gathers and deduplicates"]
    HANDLE --> COLLECT
    COLLECT --> REPORT["ReportGenerator shows 'Analysis Incomplete' indicators<br/>with actionable remediation such as role assignment commands"]
```

## Authentication Architecture

### CLI Authentication Flow

```mermaid
flowchart TD
    LOGIN["User login via az login"] --> CTX["cmd.cli_ctx (CLI context)"]
    CTX --> MGMT["get_mgmt_service_client(cli_ctx, SDKClientClass)<br/>returns pre-authenticated SDK client<br/>token refresh handled by CLI framework"]
    CTX --> PROF["Profile(cli_ctx=cmd.cli_ctx)"]
    PROF --> SUB[".get_subscription_id()<br/>returns current subscription"]
    PROF --> CRED[".get_login_credentials()<br/>returns credential, subscription_id, tenant_id"]
    MGMT --> DICT["Clients dict passed to all analyzers"]
    SUB --> DICT
    CRED --> DICT
    DICT --> CONTENTS["aks_client: ManagedClustersOperations<br/>network_client: NetworkManagementClient<br/>compute_client: ComputeManagementClient<br/>privatedns_client: PrivateDnsManagementClient<br/>subscription_id: str<br/>credential: TokenCredential"]
```

The `credential` object is also passed directly for cross-subscription scenarios where analyzers need to create ad-hoc clients for resources in different subscriptions, such as BYO Private DNS zones in a hub subscription.

## Design Decisions

### 1. Extension vs. Core Module

**Decision:** Package as an Azure CLI extension, not a submodule of the `acs` command module.

**Rationale:**
- Independent versioning and release cycle
- No modifications to existing Azure CLI files (zero merge-conflict risk)
- Users install on demand: `az extension add --name aks-net-diagnostics`
- Easier to iterate during preview/beta phase

### 2. Explicit `azure-mgmt-network` Dependency

**Decision:** Declare `azure-mgmt-network~=25.0` as the only explicit dependency in `setup.py`.

**Rationale:**
- Azure CLI 2.83+ does **not** bundle `azure-mgmt-network` (the `az network` commands ship separately)
- Other required SDKs (`azure-mgmt-compute`, `azure-mgmt-containerservice`, `azure-mgmt-privatedns`) **are** bundled with the CLI
- Using compatible-release (`~=25.0`) pins the major version while allowing minor/patch updates

### 3. Output Format Awareness

**Decision:** Detect `--output json/yaml/tsv` and suppress console printing when a structured format is requested.

**Rationale:**
- The console report uses rich markdown formatting that would be garbled in `--output json`
- When `--output json` is specified, the CLI framework serializes the returned dict; the extension should not also print to stdout
- Default (`--output table` / no flag) shows the console report as before

### 4. Five Client Factories (vs. Three in Stage 3)

**Decision:** Create dedicated factories for `cf_managed_clusters`, `cf_agent_pools`, `cf_network_client`, `cf_compute_client`, and `cf_privatedns_client`.

**Rationale:**
- Stage 3 (azure-cli fork) reused existing factories from the `acs` module; only `cf_network_client` and `cf_compute_client` were added
- As a standalone extension we must create all factories ourselves
- `cf_privatedns_client` was implicitly available in Stage 3 through shared code; now it's explicit

### 5. Permission-Aware Graceful Degradation

**Decision:** Catch `AuthorizationFailed` errors, create diagnostic findings, and continue execution with reduced data.

**Rationale:**
- Enterprise users often have limited RBAC scopes
- Partial analysis is more useful than a crash
- Findings clearly communicate what was skipped and which roles to request
- Downstream analyzers handle `None` / empty data without false positives

### 6. Orchestrator-Driven Phase Architecture

**Decision:** Central `run_diagnostics()` function coordinates all phases sequentially, passing results forward.

**Rationale:**
- Clear execution order with explicit data dependencies
- Easy to add or reorder phases
- Permission checks from early phases inform later phases
- Single point of control for result aggregation and report generation

## Code Quality

### Quality Checks

| Check | Status |
|-------|--------|
| `azdev linter` | PASSED, 0 violations |
| `azdev style` (pylint + flake8) | PASSED |
| `az aks net-diagnostics --help` | Loads correctly |
| `pip check` | No broken requirements |

## Testing Status

### Current State

The extension has **zero automated test cases**. Running `azdev test aks-net-diagnostics` completes with `0 items`, and the pre-push hook reports:

```
Error: azdev test check failed. You can check the test logs in the 'test_results.xml' file.
```

The push still succeeds because the hook exits after the test stage, but this error signals a gap that must be addressed before submitting a PR to `Azure/azure-cli-extensions`.

### Current Validation Approach

All functionality is validated through **manual live testing** against real AKS clusters. For each release, purpose-built clusters are created covering the supported configuration matrix (kubenet, Azure CNI, overlay, private clusters, proxy, NAP/Karpenter, outbound types, etc.). The diagnostic command is run against each cluster and output is verified against expected findings.

The [COVERAGE-MATRIX.md](COVERAGE-MATRIX.md) documents the scenarios tested for each release, including 21 live-tested scenarios for v0.3.0b1.

While this approach provides high confidence in real-world behavior, it is not automated, not repeatable in CI, and does not cover edge cases or regression detection.

### What Is Needed

| Test Type | Purpose | Notes |
|-----------|---------|-------|
| **Unit tests** | Validate individual FindingCode detection logic | Requires mocking Azure SDK responses (ARM, VMSS, NSG, route tables, DNS zones) |
| **Scenario tests** | End-to-end runs against recorded or mocked cluster configurations | Could use `azdev test` with recorded HTTP interactions |
| **Integration tests** | Validate against live clusters in CI | Requires test subscription, cluster provisioning, and teardown |

### Guidance Needed

Before submitting a PR to the official `Azure/azure-cli-extensions` repo, guidance is needed from the AKS Product Group on:

- **Test patterns**: Preferred mocking strategy for Azure SDK calls (e.g., `unittest.mock`, VCR.py/`pytest-recording`, or the `azure-devtools` test framework)
- **Test infrastructure**: Whether live integration tests are required or if recorded/mocked tests are sufficient for acceptance
- **CI expectations**: Minimum test coverage thresholds or specific test gates enforced by the upstream CI pipeline
- **Test data**: How to handle test fixtures for complex resources like NSGs, route tables, and VMSS run-command outputs

---

**Last Updated:** April 2026
**Status:** Preview, active development
