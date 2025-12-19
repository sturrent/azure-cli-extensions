# Plan: Converting `az aks net-diagnostics` POC to Azure CLI Preview Extension

**Date:** November 11, 2025  
**Author:** AI Assistant  
**Status:** Planning Phase

---

## Executive Summary

This document outlines the plan to convert the `az aks net-diagnostics` POC (currently in a fork of azure-cli) into a **preview Azure CLI extension**. This extension will serve as a testing and validation phase before eventual integration into the official Azure CLI as a core subcommand.

### Strategy Phases

**Phase 1 (Current Plan):** POC → Preview Extension  
**Phase 2 (Future):** Preview Extension → Official Core CLI Subcommand

This approach allows for:
- Real-world testing with actual users
- Feature validation and refinement
- Community feedback collection
- Stability verification
- Before committing to core CLI integration

---

## Table of Contents

1. [Background](#background)
2. [Goals](#goals)
3. [Repository Options](#repository-options)
4. [Extension Structure](#extension-structure)
5. [Required Changes](#required-changes)
6. [Migration Tasks](#migration-tasks)
7. [Testing Strategy](#testing-strategy)
8. [Publishing Process](#publishing-process)
9. [Timeline](#timeline)
10. [Risks & Mitigation](#risks--mitigation)

---

## Background

### Current State

- **Location:** Fork of `Azure/azure-cli` repository at `https://github.com/sturrent/azure-cli`
- **Status:** POC (Proof of Concept) implementation
- **Command:** `az aks net-diagnostics`
- **Code Location:** `src/azure-cli/azure/cli/command_modules/acs/net_diagnostics/`
- **Implementation Status:**
  - 14 diagnostic modules (~6,500 lines of code)
  - 4 modified existing files (99 lines of integration code)
  - Phase 1-7 complete + Gap Closure complete
  - Production-ready code with 10.00/10 pylint score
  - 100% test pass rate (33+ formal tests + 6+ exploration tests)

### Strategic Goal

**Short-term:** Create preview extension for real-world testing and validation  
**Long-term:** Integrate into official Azure CLI as core `az aks net-diagnostics` subcommand

### Why Start with Preview Extension?

**Validation Benefits:**
1. ✅ Real-world testing with actual AKS users
2. ✅ Collect feedback before core CLI integration
3. ✅ Validate feature completeness and usability
4. ✅ Identify edge cases and missing scenarios
5. ✅ Prove stability and reliability
6. ✅ Build user adoption and support

**Technical Benefits:**
1. ✅ Faster iteration cycles (extension updates vs CLI releases)
2. ✅ Lower risk deployment
3. ✅ Easy rollback if issues arise
4. ✅ Gradual rollout to users
5. ✅ Flexibility to add/change features based on feedback

**Path to Core CLI Integration:**

**Path to Core CLI Integration:**

Once the preview extension demonstrates:
- ✅ Stability (no critical bugs over 3-6 months)
- ✅ User adoption and positive feedback
- ✅ Complete feature coverage
- ✅ Comprehensive test coverage
- ✅ Performance validation

Then we can propose integration into official Azure CLI core as:
- Official `az aks net-diagnostics` subcommand
- Built-in to Azure CLI (no installation required)
- Maintained by Azure CLI team

---

## Goals

### Primary Goals (Preview Extension)

1. ✅ Create a **preview** Azure CLI extension with `az aks net-diagnostics` command
2. ✅ Enable real-world testing with actual AKS users
3. ✅ Maintain 100% feature parity with POC implementation
4. ✅ Preserve all diagnostic capabilities (7 analyzers, connectivity testing, reporting)
5. ✅ Keep code quality at 10.00/10 pylint standard
6. ✅ Ensure 100% test coverage

### Secondary Goals

1. ✅ Publish to Azure CLI Extensions index for discoverability
2. ✅ Set up CI/CD for automated builds and releases
3. ✅ Create comprehensive documentation (README, CONTRIBUTING, etc.)
4. ✅ Establish versioning strategy (start at **0.1.0** for preview release)
5. ✅ Collect user feedback and telemetry
6. ✅ Build case for eventual core CLI integration

### Long-term Goal (Future)

1. ⏳ Propose integration into official Azure CLI as core subcommand
2. ⏳ Transfer ownership to Azure CLI team
3. ⏳ Graduate from preview extension to built-in command

---

## Repository Options

### Option 1: Fork `Azure/azure-cli-extensions` (RECOMMENDED)

**Pros:**
- ✅ Follows Azure CLI extension conventions
- ✅ Can submit PR to include in official index
- ✅ Leverages existing CI/CD infrastructure
- ✅ Automatic builds and wheel publishing
- ✅ Community visibility

**Cons:**
- ⚠️ Must follow strict Azure contribution guidelines
- ⚠️ PR review process required for index inclusion

**Process:**
1. Fork `https://github.com/Azure/azure-cli-extensions`
2. Create extension in `src/aks-net-diagnostics/`
3. Develop and test locally
4. Submit PR to Azure/azure-cli-extensions
5. After merge, automatic CI/CD will build and publish

---

### Option 2: Create New Repository (Alternative)

**Pros:**
- ✅ Full control over repository
- ✅ Custom CI/CD workflow
- ✅ Faster initial setup

**Cons:**
- ⚠️ Manual wheel building and hosting
- ⚠️ Manual index.json updates
- ⚠️ Less discoverable
- ⚠️ No automatic publishing

**Process:**
1. Create new repo: `https://github.com/<your-org>/aks-net-diagnostics-extension`
2. Set up extension structure
3. Build wheel manually
4. Host wheel on Azure Storage or GitHub Releases
5. Optionally submit PR to update index.json

---

## Extension Structure

### Directory Layout

```
azure-cli-extensions/
└── src/
    └── aks-net-diagnostics/              # Extension root
        ├── setup.py                       # 📦 Package definition
        ├── setup.cfg                      # (optional) Setup configuration
        ├── README.md                      # 📖 Extension documentation
        ├── HISTORY.rst                    # 📝 Changelog
        ├── CONTRIBUTING.md                # (optional) Contribution guide
        ├── LICENSE                        # (optional, inherits from repo)
        │
        └── azext_aks_net_diagnostics/     # Main Python package
            ├── __init__.py                # Package initialization + loader
            ├── _help.py                   # Help text definitions
            ├── commands.py                # Command registration
            ├── _params.py                 # Parameter definitions
            ├── custom.py                  # Command handler functions
            ├── _client_factory.py         # Azure SDK client factories
            ├── azext_metadata.json        # 🔑 Extension metadata
            │
            ├── _version.py                # Version info
            ├── exceptions.py              # Exception classes
            ├── models.py                  # Data models
            ├── validators.py              # Input validators
            │
            ├── orchestrator.py            # Main diagnostic coordinator
            ├── base_analyzer.py           # Base analyzer class
            ├── cluster_data_collector.py  # Data collection from Azure
            ├── report_generator.py        # Output formatting
            │
            ├── nsg_analyzer.py            # NSG analysis
            ├── dns_analyzer.py            # DNS configuration analysis
            ├── route_table_analyzer.py    # UDR analysis
            ├── api_server_analyzer.py     # API server access analysis
            ├── outbound_analyzer.py       # Outbound connectivity analysis
            ├── connectivity_tester.py     # Active connectivity testing
            ├── misconfiguration_analyzer.py  # Cross-component correlation
            │
            └── tests/                     # Test modules
                ├── __init__.py
                ├── latest/
                │   ├── __init__.py
                │   └── test_aks_net_diagnostics.py
                └── recordings/            # Test recordings
```

---

## Required Changes

### 1. Files to Copy (From Core Module)

**Source:** `azure-cli/src/azure-cli/azure/cli/command_modules/acs/net_diagnostics/`

**Diagnostic Modules (14 files - unchanged):**
- ✅ `orchestrator.py`
- ✅ `base_analyzer.py`
- ✅ `cluster_data_collector.py`
- ✅ `report_generator.py`
- ✅ `nsg_analyzer.py`
- ✅ `dns_analyzer.py`
- ✅ `route_table_analyzer.py`
- ✅ `api_server_analyzer.py`
- ✅ `outbound_analyzer.py`
- ✅ `connectivity_tester.py`
- ✅ `misconfiguration_analyzer.py`
- ✅ `models.py`
- ✅ `exceptions.py`
- ✅ `validators.py`
- ✅ `_version.py` (update version)

---

### 2. Files to Create (Extension-Specific)

**New Files Required:**

#### `setup.py` (Package Definition)
```python
#!/usr/bin/env python

from codecs import open
from setuptools import setup, find_packages

VERSION = "0.1.0"  # Preview version

CLASSIFIERS = [
    'Development Status :: 4 - Beta',  # Preview status
    'Intended Audience :: Developers',
    'Intended Audience :: System Administrators',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.10',
    'Programming Language :: Python :: 3.11',
    'Programming Language :: Python :: 3.12',
    'Programming Language :: Python :: 3.13',
    'License :: OSI Approved :: MIT License',
]

# Dependencies already in azure-cli-core or azure-cli
# Do NOT include: azure-cli-core, knack, etc. (already available)
DEPENDENCIES = [
    # Only add if NOT in azure-cli-core/azure-cli setup.py
    # Currently all dependencies are already available
]

with open('README.md', 'r', encoding='utf-8') as f:
    README = f.read()
with open('HISTORY.rst', 'r', encoding='utf-8') as f:
    HISTORY = f.read()

setup(
    name='aks-net-diagnostics',
    version=VERSION,
    description='Microsoft Azure Command-Line Tools AKS Network Diagnostics Extension (Preview)',
    long_description=README + '\n\n' + HISTORY,
    license='MIT',
    author='Microsoft Corporation',
    author_email='azpycli@microsoft.com',
    url='https://github.com/Azure/azure-cli-extensions/tree/main/src/aks-net-diagnostics',
    classifiers=CLASSIFIERS,
    packages=find_packages(),
    install_requires=DEPENDENCIES,
    package_data={'azext_aks_net_diagnostics': ['azext_metadata.json']},
)
```

#### `azext_metadata.json` (Extension Metadata)

```json
{
    "azext.minCliCoreVersion": "2.60.0",
    "azext.maxCliCoreVersion": null,
    "azext.isPreview": true,
    "azext.isExperimental": false
}
```

**Metadata Fields:**
- `azext.minCliCoreVersion`: Minimum Azure CLI version (2.60.0 = stable, widely deployed)
- `azext.maxCliCoreVersion`: Maximum Azure CLI version (null = no limit)
- `azext.isPreview`: **true** (preview extension for testing and validation)
- `azext.isExperimental`: false (code is stable, not experimental)

#### `__init__.py` (Package Loader)
```python
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core import AzCommandsLoader
from azext_aks_net_diagnostics._help import helps  # pylint: disable=unused-import


class AksNetDiagnosticsCommandsLoader(AzCommandsLoader):
    def __init__(self, cli_ctx=None):
        from azure.cli.core.commands import CliCommandType
        aks_net_diagnostics_custom = CliCommandType(
            operations_tmpl='azext_aks_net_diagnostics.custom#{}')
        super().__init__(cli_ctx=cli_ctx, custom_command_type=aks_net_diagnostics_custom)

    def load_command_table(self, args):
        from azext_aks_net_diagnostics.commands import load_command_table
        load_command_table(self, args)
        return self.command_table

    def load_arguments(self, command):
        from azext_aks_net_diagnostics._params import load_arguments
        load_arguments(self, command)


COMMAND_LOADER_CLS = AksNetDiagnosticsCommandsLoader
```

#### `commands.py` (Command Registration)
```python
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core.commands import CliCommandType
from azext_aks_net_diagnostics._client_factory import cf_managed_clusters


def load_command_table(self, _):
    managed_clusters_sdk = CliCommandType(
        operations_tmpl='azure.mgmt.containerservice.operations#ManagedClustersOperations.{}',
        client_factory=cf_managed_clusters
    )

    with self.command_group('aks', managed_clusters_sdk, 
                           client_factory=cf_managed_clusters) as g:
        g.custom_command('net-diagnostics', 'aks_net_diagnostics')
```

#### `_params.py` (Parameter Definitions)
```python
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------


def load_arguments(self, _):
    with self.argument_context('aks net-diagnostics') as c:
        c.argument('resource_group_name', options_list=['--resource-group', '-g'],
                   help='Name of resource group')
        c.argument('name', options_list=['--name', '-n'],
                   help='Name of the managed cluster')
        c.argument('details', action='store_true',
                   help='Show detailed diagnostic information')
        c.argument('probe_test', action='store_true',
                   help='Perform active connectivity tests from cluster nodes')
        c.argument('json_report', options_list=['--json-report'],
                   help='Path to save JSON report file')
```

#### `custom.py` (Command Handler)
```python
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from knack.log import get_logger
from azext_aks_net_diagnostics._client_factory import (
    cf_network_client,
    cf_compute_client
)
from azext_aks_net_diagnostics.orchestrator import run_diagnostics

logger = get_logger(__name__)


def aks_net_diagnostics(cmd, client, resource_group_name, name,
                       details=False, probe_test=False, json_report=None):
    """
    Run network diagnostics for an AKS cluster.
    
    :param cmd: Command context
    :param client: ManagedClustersOperations client
    :param resource_group_name: Resource group name
    :param name: Cluster name
    :param details: Show detailed output
    :param probe_test: Run connectivity tests
    :param json_report: Path to save JSON report
    """
    logger.info("Starting AKS network diagnostics for cluster: %s", name)
    
    # Get subscription from CLI context
    from azure.cli.core.commands.client_factory import get_subscription_id
    subscription_id = get_subscription_id(cmd.cli_ctx)
    
    # Create authenticated Azure SDK clients using CLI context
    network_client = cf_network_client(cmd.cli_ctx, subscription_id)
    compute_client = cf_compute_client(cmd.cli_ctx, subscription_id)
    
    # Run diagnostic orchestrator
    run_diagnostics(
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
        cluster_name=name,
        aks_client=client,
        network_client=network_client,
        compute_client=compute_client,
        details=details,
        probe_test=probe_test,
        json_report=json_report
    )
```

#### `_client_factory.py` (Client Factories)
```python
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core.commands.client_factory import get_mgmt_service_client


def cf_managed_clusters(cli_ctx, *_):
    from azure.mgmt.containerservice import ContainerServiceClient
    return get_mgmt_service_client(cli_ctx, ContainerServiceClient).managed_clusters


def cf_network_client(cli_ctx, subscription_id=None):
    from azure.mgmt.network import NetworkManagementClient
    return get_mgmt_service_client(cli_ctx, NetworkManagementClient,
                                   subscription_id=subscription_id)


def cf_compute_client(cli_ctx, subscription_id=None):
    from azure.mgmt.compute import ComputeManagementClient
    return get_mgmt_service_client(cli_ctx, ComputeManagementClient,
                                   subscription_id=subscription_id)
```

#### `_help.py` (Help Text)
```python
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from knack.help_files import helps


helps['aks net-diagnostics'] = """
    type: command
    short-summary: Run network diagnostics for an AKS cluster.
    long-summary: |
        Diagnose network configuration issues in Azure Kubernetes Service (AKS) clusters.
        
        This command analyzes:
        - Network Security Group (NSG) rules
        - User Defined Routes (UDRs)
        - DNS configuration
        - API server access
        - Outbound connectivity
        - Private cluster settings
        - Connectivity tests (optional with --probe-test)
    
    examples:
        - name: Run basic network diagnostics
          text: az aks net-diagnostics -g myResourceGroup -n myCluster
        
        - name: Run diagnostics with detailed output
          text: az aks net-diagnostics -g myResourceGroup -n myCluster --details
        
        - name: Run diagnostics with connectivity tests
          text: az aks net-diagnostics -g myResourceGroup -n myCluster --probe-test
        
        - name: Run diagnostics and save JSON report
          text: az aks net-diagnostics -g myResourceGroup -n myCluster --json-report report.json
        
        - name: Full diagnostic with all options
          text: az aks net-diagnostics -g myResourceGroup -n myCluster --details --probe-test --json-report report.json
"""
```

#### `README.md` (Extension Documentation)

```markdown
# AKS Network Diagnostics Extension (Preview)

**⚠️ PREVIEW:** This extension is in preview. Features and behavior may change based on user feedback.

Microsoft Azure CLI Extension for AKS network diagnostics.

## Installation

```bash
az extension add --name aks-net-diagnostics
```

## Usage

```bash
# Basic diagnostics
az aks net-diagnostics -g myResourceGroup -n myCluster

# Detailed output
az aks net-diagnostics -g myResourceGroup -n myCluster --details

# With connectivity tests
az aks net-diagnostics -g myResourceGroup -n myCluster --probe-test

# Save JSON report
az aks net-diagnostics -g myResourceGroup -n myCluster --json-report report.json
```

## Features

- Network Security Group (NSG) analysis
- User Defined Routes (UDR) impact assessment
- DNS configuration validation
- API server access analysis
- Outbound connectivity analysis
- Private cluster diagnostics
- Active connectivity testing
- Misconfiguration detection

## Preview Status

This is a **preview extension** for testing and validation. We encourage you to:
- Try it with your AKS clusters
- Report bugs and issues on GitHub
- Provide feedback on features and usability
- Share your use cases

Your feedback will help us improve this tool before proposing it for integration into the official Azure CLI.

## Requirements

- Azure CLI 2.60.0 or higher
- Python 3.10, 3.11, 3.12, or 3.13

## Contributing

See CONTRIBUTING.md for development guidelines.

## License

MIT
```

#### `HISTORY.rst` (Changelog)

```rst
.. :changelog:

Release History
===============

0.1.0
+++++
* Initial preview release
* **PREVIEW:** This extension is in preview for testing and validation
* Comprehensive network diagnostics for AKS clusters
* Support for all AKS networking modes (kubenet, Azure CNI, Azure CNI Overlay)
* NSG, UDR, DNS, API server, and outbound connectivity analysis
* Active connectivity testing from cluster nodes
* Permission-aware analysis with actionable remediation
* Azure CNI Overlay NSG validation
* User-assigned NAT Gateway support
* API Server VNet Integration support
* BYO Private DNS Zone cross-subscription support
* Virtual Machines node pools support
* Mixed VMSS+VM cluster support

Future Releases
+++++++++++++++
* 0.2.x - Bug fixes and minor improvements based on user feedback
* 0.3.x - Additional features and enhancements
* 1.0.0 - Stable release (after validation period)
```

---

### 3. Files to Modify (Update Imports)

**Changes Required:**

All imports in diagnostic modules need to change from:
```python
from azure.cli.command_modules.acs.net_diagnostics.models import Finding
```

To:
```python
from azext_aks_net_diagnostics.models import Finding
```

**Files to Update:**
- `orchestrator.py` - Update all internal imports
- `base_analyzer.py` - Update import paths
- `cluster_data_collector.py` - Update import paths
- All 7 analyzer modules - Update import paths
- `report_generator.py` - Update import paths

**Automated Script:**
```bash
# Run this in the extension directory
find azext_aks_net_diagnostics -name "*.py" -type f -exec sed -i \
  's/from azure\.cli\.command_modules\.acs\.net_diagnostics\./from azext_aks_net_diagnostics./g' {} \;
```

---

### 4. Remove from Core Module

**NOT APPLICABLE FOR PREVIEW EXTENSION**

Since this is a POC in your fork (not in official Azure CLI), there's nothing to remove from the core module. The extension will be the first public release of this tool.

**Future:** If/when this gets integrated into official Azure CLI core after the preview period, the extension can be deprecated and users will be guided to use the built-in command.

---

## Migration Tasks

### Phase 1: Repository Setup (2-4 hours) ✅ COMPLETED

- [x] **Task 1.1:** Choose repository option (Fork vs New Repo)
  - **Recommendation:** Fork `Azure/azure-cli-extensions`
  - **Action:** Forked repository to https://github.com/sturrent/azure-cli-extensions
  - **Estimated time:** 15 minutes
  - **Status:** ✅ DONE

- [x] **Task 1.2:** Clone forked repository
  ```bash
  git clone https://github.com/sturrent/azure-cli-extensions.git
  cd azure-cli-extensions
  git checkout -b aks-net-diagnostics-extension
  ```
  - **Estimated time:** 10 minutes
  - **Status:** ✅ DONE - Cloned to `/home/sturrent/gitrepos/azure-cli-extensions`

- [x] **Task 1.3:** Create extension directory structure
  ```bash
  mkdir -p src/aks-net-diagnostics/azext_aks_net_diagnostics/tests/latest
  ```
  - **Estimated time:** 5 minutes
  - **Status:** ✅ DONE

---

### Phase 2: Code Migration (4-6 hours) ✅ COMPLETED

- [x] **Task 2.1:** Copy diagnostic modules from your fork
  ```bash
  # Copy all 14 diagnostic modules from your azure-cli fork
  cp -r /home/sturrent/gitrepos/azure-cli/src/azure-cli/azure/cli/command_modules/acs/net_diagnostics/*.py \
    azure-cli-extensions/src/aks-net-diagnostics/azext_aks_net_diagnostics/
  ```
  - **Files:** orchestrator.py, analyzers, collectors, etc. (17 files total, ~340KB)
  - **Estimated time:** 30 minutes
  - **Status:** ✅ DONE - All 17 files copied successfully

- [x] **Task 2.2:** Update import statements
  ```bash
  # Automated import replacement
  cd azure-cli-extensions/src/aks-net-diagnostics
  find azext_aks_net_diagnostics -name "*.py" -exec sed -i \
    's/from azure\.cli\.command_modules\.acs\.net_diagnostics\./from azext_aks_net_diagnostics./g' {} \;
  ```
  - **Estimated time:** 1 hour (includes validation)
  - **Status:** ✅ DONE - All imports updated and verified

- [x] **Task 2.3:** Create extension-specific files
  - [x] Create `azext_metadata.json` - ✅ DONE
  - [x] Update `_version.py` to 0.1.0b1 - ✅ DONE
  - [x] Create `setup.py` - ✅ DONE
  - [x] Update `__init__.py` (loader) - ✅ DONE
  - [x] Create `commands.py` - ✅ DONE
  - [x] Create `_params.py` - ✅ DONE
  - [x] Create `custom.py` - ✅ DONE
  - [x] Create `_client_factory.py` - ✅ DONE
  - [x] Create `_help.py` - ✅ DONE
  - **Estimated time:** 2 hours
  - **Status:** ✅ COMPLETE (9/9 files created)

- [x] **Task 2.4:** Create documentation files
  - [x] Create `README.md` - ✅ DONE (with read-only disclaimer and accurate features)
  - [x] Create `HISTORY.rst` - ✅ DONE (with actual functionality described)
  - [x] Create `CONTRIBUTING.md` - ✅ DONE
  - **Estimated time:** 1 hour
  - **Status:** ✅ COMPLETE

- [x] **Task 2.5:** Documentation accuracy improvements
  - [x] Added read-only analysis disclaimer
  - [x] Clarified permission requirements and user credential usage
  - [x] Corrected DNS analyzer description (VNET DNS + private DNS zones)
  - [x] Removed incorrect claims (firewall rules, load balancer health probes, CoreDNS)
  - [x] Clarified --probe-test functionality (DNS + outbound connectivity from nodes)
  - [x] Updated severity levels to actual values (INFO, WARNING, ERROR, CRITICAL)
  - **Status:** ✅ COMPLETE

---

### Phase 3: Local Testing (3-4 hours) ✅ COMPLETED

- [x] **Task 3.1:** Set up development environment
  ```bash
  # Install azdev
  pip install azdev
  
  # Setup azdev for extensions
  azdev setup -r /home/sturrent/gitrepos/azure-cli-extensions
  ```
  - **Estimated time:** 30 minutes
  - **Status:** ✅ DONE - Python venv at ~/.virtualenvs/azdev, azdev 0.2.8, Azure CLI 2.79.0

- [x] **Task 3.2:** Install extension in dev mode
  ```bash
  azdev extension add aks-net-diagnostics
  ```
  - **Estimated time:** 15 minutes
  - **Status:** ✅ DONE - Extension installed and working

- [x] **Task 3.3:** Run style and linter checks
  ```bash
  azdev style aks-net-diagnostics
  azdev linter aks-net-diagnostics
  ```
  - **Goal:** Maintain 10.00/10 pylint score
  - **Estimated time:** 1 hour (fix any issues)
  - **Status:** ✅ DONE - Flake8: PASSED, Pylint: PASSED

- [x] **Task 3.4:** Test with real AKS clusters
  - **Clusters tested:** 3+ configurations (public, private with BYO DNS, clusters with NSG issues)
  - **Tests performed:**
    - Basic command execution ✅
    - --details flag ✅
    - --json-report flag ✅
    - --probe-test flag (4 connectivity tests from nodes) ✅
    - Combined flags ✅
  - **Goal:** Verify all diagnostic functionality
  - **Estimated time:** 1 hour
  - **Status:** ✅ DONE - All tests passed, see PHASE3-TEST-RESULTS.md

- [x] **Task 3.5:** Validation results
  - Network plugin detection accurate (Azure CNI, Azure CNI Overlay) ✅
  - NSG analysis detecting actual blocking rules ✅
  - Private DNS zone detection working ✅
  - API server configuration analysis correct ✅
  - Severity levels appropriate (INFO, WARNING, ERROR, CRITICAL) ✅
  - Read-only operation confirmed ✅
  - No critical bugs found ✅
  - **Estimated time:** 1 hour
  - **Status:** ✅ COMPLETE - Extension production-ready for preview

---

### Phase 4: Build & Package (1-2 hours) - PENDING

- [ ] **Task 4.1:** Build extension wheel
  ```bash
  azdev extension build aks-net-diagnostics
  ```
  - **Output:** `dist/aks_net_diagnostics-0.1.0-py3-none-any.whl`
  - **Estimated time:** 15 minutes

- [ ] **Task 4.2:** Test installation from wheel
  ```bash
  # Uninstall dev version
  azdev extension remove aks-net-diagnostics
  
  # Install from wheel
  az extension add --source dist/aks_net_diagnostics-0.1.0-py3-none-any.whl
  
  # Verify
  az extension list
  az aks net-diagnostics --help
  ```
  - **Estimated time:** 30 minutes

- [ ] **Task 4.3:** Test on clean environment
  - Create fresh virtual environment
  - Install Azure CLI
  - Install extension wheel
  - Run functional tests
  - **Estimated time:** 1 hour

---

### Phase 5: Documentation (2-3 hours)

- [ ] **Task 5.1:** Update README.md
  - Installation instructions
  - **Preview status warning**
  - Usage examples
  - Feature list
  - **Feedback collection information**
  - Requirements
  - **Estimated time:** 1 hour

- [ ] **Task 5.2:** Update HISTORY.rst
  - Version 0.1.0 preview release notes
  - Feature highlights
  - **Preview disclaimer**
  - **Estimated time:** 30 minutes

- [ ] **Task 5.3:** Create CONTRIBUTING.md
  - Development setup
  - Testing guidelines
  - Code style requirements
  - **Estimated time:** 1 hour

- [ ] **Task 5.4:** Add examples to help text
  - Review `_help.py`
  - Add practical examples
  - **Estimated time:** 30 minutes

---

### Phase 6: CI/CD Setup (2-3 hours)

**If using Azure/azure-cli-extensions (auto-configured):**
- [ ] **Task 6.1:** Verify CI/CD runs on PR
  - Automatic build
  - Automatic testing
  - Automatic wheel publishing (after merge)
  - **Estimated time:** 1 hour (monitoring)

**If using custom repository:**
- [ ] **Task 6.1:** Set up GitHub Actions
  - Create `.github/workflows/ci.yml`
  - Configure build, test, publish workflow
  - **Estimated time:** 2 hours

- [ ] **Task 6.2:** Set up Azure Storage for wheel hosting
  - Create storage account
  - Configure public access
  - **Estimated time:** 1 hour

---

### Phase 7: Publishing (2-4 hours)

#### Option A: Publishing via Azure/azure-cli-extensions (RECOMMENDED)

- [ ] **Task 7.1:** Submit PR to Azure/azure-cli-extensions
  - Create PR with extension code
  - Fill out PR template
  - Address review comments
  - **Estimated time:** 1 hour + review time

- [ ] **Task 7.2:** Wait for CI/CD to build and publish
  - Automatic after merge
  - Wheel published to storage
  - **Estimated time:** Automatic

- [ ] **Task 7.3:** Wait for index.json update
  - Automatic PR created
  - Review and approve
  - **Estimated time:** 1 hour

#### Option B: Manual Publishing (Custom Repo)

- [ ] **Task 7.1:** Upload wheel to hosting location
  - Azure Storage / GitHub Releases
  - **Estimated time:** 30 minutes

- [ ] **Task 7.2:** Calculate SHA256 hash
  ```bash
  shasum -a 256 dist/aks_net_diagnostics-1.0.0-py3-none-any.whl
  ```
  - **Estimated time:** 5 minutes

- [ ] **Task 7.3:** Update index.json (optional)
  - Fork Azure/azure-cli-extensions
  - Update `src/index.json`
  - Submit PR
  - **Estimated time:** 2 hours

---

### Phase 8: Verification (1-2 hours)

- [ ] **Task 8.1:** Test installation from index
  ```bash
  az extension add --name aks-net-diagnostics
  ```
  - **Estimated time:** 15 minutes

- [ ] **Task 8.2:** Verify discoverability
  ```bash
  az extension list-available | grep aks-net-diagnostics
  ```
  - **Estimated time:** 10 minutes

- [ ] **Task 8.3:** Run full test suite
  - Install extension
  - Run all 33+ tests
  - Verify 100% pass rate
  - **Estimated time:** 1 hour

---

## Testing Strategy

### Unit Tests
- ✅ Reuse existing 33+ tests from core module
- ✅ Add extension-specific tests (installation, command registration)
- ✅ Goal: 100% test coverage maintained

### Integration Tests
- ✅ Test with real AKS clusters (5 test clusters)
- ✅ All network types (Overlay, Kubenet, Azure CNI Pod Subnet)
- ✅ All outbound types (LoadBalancer, NAT Gateway, UDR)
- ✅ Permission scenarios (full + limited)

### Compatibility Tests

- ✅ Test with Azure CLI 2.60.0+ (minimum version for preview)
- ✅ Test with Python 3.10, 3.11, 3.12, 3.13
- ✅ Test on Linux, macOS, Windows

### Regression Tests

- ✅ Compare extension output to POC implementation
- ✅ Verify identical behavior
- ✅ No regressions in features

### Preview-Specific Tests

- ✅ Verify preview warning is displayed
- ✅ Test feedback collection mechanisms
- ✅ Validate telemetry (if implemented)
- ✅ Test with various Azure CLI versions (2.60.0, 2.70.0, latest)

---

## Publishing Process

### Index.json Entry

**After building wheel, add to index.json:**

```json
{
  "aks-net-diagnostics": [
    {
      "filename": "aks_net_diagnostics-0.1.0-py3-none-any.whl",
      "sha256Digest": "<calculated-hash>",
      "downloadUrl": "https://<storage-url>/aks_net_diagnostics-0.1.0-py3-none-any.whl",
      "metadata": {
        "azext.minCliCoreVersion": "2.60.0",
        "azext.isPreview": true,
        "azext.isExperimental": false,
        "classifiers": [
          "Development Status :: 4 - Beta",
          "Intended Audience :: Developers",
          "Intended Audience :: System Administrators",
          "Programming Language :: Python",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.10",
          "Programming Language :: Python :: 3.11",
          "Programming Language :: Python :: 3.12",
          "Programming Language :: Python :: 3.13",
          "License :: OSI Approved :: MIT License"
        ],
        "extensions": {
          "python.details": {
            "contacts": [
              {
                "email": "azpycli@microsoft.com",
                "name": "Microsoft Corporation",
                "role": "author"
              }
            ],
            "document_names": {
              "description": "DESCRIPTION.rst"
            },
            "project_urls": {
              "Home": "https://github.com/Azure/azure-cli-extensions/tree/main/src/aks-net-diagnostics"
            }
          }
        },
        "generator": "bdist_wheel (0.43.0)",
        "license": "MIT",
        "metadata_version": "2.1",
        "name": "aks-net-diagnostics",
        "summary": "Microsoft Azure Command-Line Tools AKS Network Diagnostics Extension (Preview)",
        "version": "0.1.0"
      }
    }
  ]
}
```

**Automated index update:**
```bash
azdev extension update-index <wheel-url>
```

---

## Timeline

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Phase 1: Repository Setup | 2-4 hours | 2-4 hours |
| Phase 2: Code Migration | 4-6 hours | 6-10 hours |
| Phase 3: Local Testing | 3-4 hours | 9-14 hours |
| Phase 4: Build & Package | 1-2 hours | 10-16 hours |
| Phase 5: Documentation | 2-3 hours | 12-19 hours |
| Phase 6: CI/CD Setup | 2-3 hours | 14-22 hours |
| Phase 7: Publishing | 2-4 hours | 16-26 hours |
| Phase 8: Verification | 1-2 hours | 17-28 hours |
| **TOTAL** | **17-28 hours** | **~3-4 days** |

**Assumptions:**
- Working on this as a focused effort
- Minimal review cycles
- No major blockers

**Note:** PR review time for `Azure/azure-cli-extensions` is NOT included (can vary widely)

---

## Risks & Mitigation

### Risk 1: Dependency Conflicts

**Risk:** Extension might require dependencies that conflict with Azure CLI core.

**Mitigation:**
- ✅ Use only dependencies already in `azure-cli-core` and `azure-cli`
- ✅ Review `setup.py` in both packages
- ✅ Keep `DEPENDENCIES = []` in extension `setup.py`
- ✅ All required packages are already available:
  - `azure-mgmt-containerservice`
  - `azure-mgmt-network`
  - `azure-mgmt-compute`
  - `colorama`
  - `packaging`

---

### Risk 2: Breaking Changes in Azure CLI

**Risk:** Future Azure CLI updates might break extension compatibility.

**Mitigation:**
- ✅ Set `azext.minCliCoreVersion` to current version (2.78.0)
- ✅ Set `azext.maxCliCoreVersion` to null (no upper limit)
- ✅ Test with each new Azure CLI release
- ✅ Update extension version if breaking changes occur
- ✅ Use stable Azure SDK APIs

---

### Risk 3: User Confusion (Extension vs Core)

**Risk:** Users might not know they need to install the extension.

**Mitigation:**
- ✅ Clear installation instructions in README
- ✅ Add to official Azure CLI extensions list
- ✅ Create documentation on Microsoft Docs
- ✅ If core module is removed, show helpful error:
  ```
  'az aks net-diagnostics' is not a core command.
  Install the extension with: az extension add --name aks-net-diagnostics
  ```

---

### Risk 4: Test Coverage Loss

**Risk:** Some tests might not work in extension context.

**Mitigation:**
- ✅ Port all 33+ existing tests to extension
- ✅ Add extension-specific tests
- ✅ Run full test suite before each release
- ✅ Maintain 100% test pass rate
- ✅ Use test recordings to speed up CI

---

### Risk 5: CI/CD Failures

**Risk:** Automated builds might fail in Azure CLI Extensions repo.

**Mitigation:**
- ✅ Test locally with `azdev extension build`
- ✅ Follow existing extension patterns
- ✅ Use compatible Python versions (3.10-3.13)
- ✅ Ensure all linter checks pass (10.00/10 pylint)
- ✅ Monitor CI/CD pipeline after PR submission

---

## Success Criteria

### Must Have ✅

1. ✅ Extension installs cleanly via `az extension add --name aks-net-diagnostics`
2. ✅ 100% feature parity with POC implementation
3. ✅ All 33+ tests passing
4. ✅ Pylint score maintained at 10.00/10
5. ✅ Zero dependency additions
6. ✅ Works with Azure CLI 2.60.0+
7. ✅ Supports Python 3.10, 3.11, 3.12, 3.13
8. ✅ **Preview status clearly indicated**

### Should Have ✅

1. ✅ Listed in `az extension list-available`
2. ✅ Published to official Azure CLI Extensions index
3. ✅ Comprehensive README and HISTORY with preview disclaimer
4. ✅ CI/CD for automated builds
5. ✅ Help text with examples
6. ✅ **Feedback collection mechanism**

### Nice to Have

1. **Preview-specific features:**
   - Telemetry for usage tracking (anonymized)
   - In-app feedback prompts
   - Preview banner in output
2. Documentation on Microsoft Docs
3. Blog post announcing preview release
4. Video tutorial
5. Community engagement plan

---

## Next Steps

### Immediate Actions (This Week)

1. **Decision:** Choose repository option (Fork vs New Repo)
   - **Recommendation:** Fork `Azure/azure-cli-extensions` for official listing

2. **Action:** Set up repository and directory structure

3. **Action:** Begin Phase 2 (Code Migration from your fork)

### Short-Term (Next 2-4 Weeks)

1. Complete all migration phases (1-8)
2. Submit PR to Azure/azure-cli-extensions
3. Address review comments
4. Publish **0.1.0 preview** extension

### Medium-Term (Next 3-6 Months - Preview Period)

1. **Monitor user feedback and bug reports**
2. Release iterative updates (0.1.x, 0.2.x, 0.3.x)
3. Add features based on community requests
4. Collect usage telemetry and metrics
5. Document common issues and solutions
6. Build case studies and success stories

### Long-Term (6-12+ Months - Path to Core CLI)

1. **Achieve stability metrics:**
   - No critical bugs for 3+ months
   - High user adoption and satisfaction
   - Comprehensive test coverage validation
   - Performance benchmarks met
   
2. **Prepare proposal for core CLI integration:**
   - Usage statistics and adoption metrics
   - Community feedback summary
   - Stability and reliability evidence
   - Maintenance plan
   
3. **Submit proposal to Azure CLI team:**
   - Formal RFC (Request for Comments)
   - Integration design document
   - Migration plan for extension users
   - Deprecation timeline for extension

4. **If approved:**
   - Integrate into official Azure CLI as `az aks net-diagnostics`
   - Deprecate preview extension
   - Guide users to built-in command

---

## Questions & Decisions

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| **Extension Name:** `aks-net-diagnostics` | Clear, descriptive, follows Azure CLI naming conventions |
| **Initial Version:** 0.1.0 | Preview release for testing and validation |
| **Preview Flag:** true | This is a preview extension, not stable yet |
| **Min CLI Version:** 2.60.0 | Stable version, widely deployed |
| **Python Versions:** 3.10-3.13 | Matches Azure CLI support |
| **Development Status:** 4 - Beta | Preview/beta status in classifiers |

### Open Questions

1. **Q:** What's the target timeline for graduating from preview to stable (1.0.0)?
   - **A:** Based on user feedback, aiming for 6-12 months validation period

2. **Q:** Should we add telemetry to track usage and issues?
   - **A:** Yes, anonymized telemetry would help understand usage patterns and issues

3. **Q:** What's the success criteria for proposing core CLI integration?
   - **A:** 
     - No critical bugs for 3+ months
     - Positive user feedback from 50+ users
     - High test coverage maintained (100%)
     - Proven stability across various AKS configurations

4. **Q:** Should we support older Azure CLI versions (e.g., 2.40.0+)?
   - **A:** Start with 2.60.0 (stable, recent), can lower if testing shows compatibility

5. **Q:** Who will maintain the extension during preview period?
   - **A:** You (initial author), with community contributions welcomed

6. **Q:** How to collect user feedback?
   - **A:** 
     - GitHub Issues for bug reports
     - GitHub Discussions for feature requests
     - Optional in-app feedback prompts
     - Survey after major releases

7. **Q:** What if Microsoft/Azure CLI team doesn't approve core integration?
   - **A:** Extension can continue as standalone tool, still valuable for community

---

## Resources

### Documentation
- [Azure CLI Extension Authoring](https://github.com/Azure/azure-cli/blob/dev/doc/extensions/authoring.md)
- [Azure CLI Extension Publishing](https://github.com/Azure/azure-cli-extensions#about-extension-publishing)
- [Azure CLI Dev Tools (azdev)](https://github.com/Azure/azure-cli-dev-tools)
- [Semantic Versioning](https://semver.org/)

### Repositories
- [Azure CLI](https://github.com/Azure/azure-cli)
- [Azure CLI Extensions](https://github.com/Azure/azure-cli-extensions)
- [AKS Net-Diagnostics (azure-sdk branch)](https://github.com/sturrent/aks-net-diagnostics/tree/azure-sdk)

### Tools
- `azdev` - Azure CLI development tools
- `pylint` - Python linter
- `flake8` - Style checker

---

**Last Updated:** November 11, 2025  
**Status:** Planning Complete - Ready for Preview Extension Implementation  
**Target:** 0.1.0 Preview Release  
**Estimated Effort:** 17-28 hours (3-4 focused days)  
**Long-term Goal:** Graduate to official Azure CLI core subcommand after validation period
