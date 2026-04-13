Release History
===============

0.3.0b1 (2026-04-13)
++++++++++++++++++++

**Feature Enhancements**

* **Network-Isolated Cluster Support**: Recognize outbound type ``none`` and ``block``, validate bootstrap ACR, suppress false-positive outbound findings
* **HTTP Proxy Diagnostics**: Detect ``httpProxyConfig``, validate proxy VNet reachability via peering, NSG proxy compliance, active probe through proxy
* **Service Tags in Authorized IP Ranges**: Detect service tag entries, warn about single-tag limit and VNet Integration conflict
* **Node Auto-Provisioning (NAP) Detection**: Detect NAP-enabled clusters, identify Karpenter-managed VMs and VMSS, warn about unanalyzed subnets
* **defaultOutboundAccess Awareness**: Surface subnet-level ``defaultOutboundAccess`` status (suppressed from CLI, preserved in JSON)
* **Bootstrap ACR Private DNS Check**: CRITICAL validation that ``privatelink.azurecr.io`` zone is linked to node VNet
* **NSG Network Isolation Adaptation**: Adapted required rules for ``none``/``block`` clusters (only DNS required)
* **Bootstrap ACR Probe Tests**: DNS + HTTPS probes targeting bootstrap ACR for network-isolated clusters
* **VM Node Pool Support**: Connectivity tester fallback to ``virtualMachines.runCommand`` for VirtualMachines-type agent pools
* Removed NTP (UDP 123) from required NSG outbound rules — AKS nodes use chrony with PTP from the hypervisor
* 12 new finding codes (27 total)

0.2.0b2 (2026-02-18)
++++++++++++++++++++

**Bug Fixes**

* Fixed ``ModuleNotFoundError: azure.mgmt.network`` when running with Azure CLI 2.83+
* Removed unnecessary pinned SDK dependencies (compute, containerservice, privatedns) that are bundled with Azure CLI
* Only ``azure-mgmt-network`` is declared as an explicit dependency since it is no longer bundled in Azure CLI 2.83+

0.2.0b1 (2025-11-12)
++++++++++++++++++++

**Feature Enhancements**

* **Output Format Support**: Added full support for Azure CLI output formats (`-o json`, `-o yaml`, `-o tsv`, `-o table`)
* Console report automatically suppressed when using non-table output formats
* Optimized JSON generation for better performance (generate once, reuse for file and output)
* Improved JSON structure with better key ordering (findings appear at end for easier visibility)
* **Code Cleanup**: Removed unused `failure_analysis` field from JSON output
* Updated documentation with output format usage examples

0.1.0b1 (2025-11-11)
++++++++++++++++++++

**Initial Preview Release**

This is the first beta release of the AKS Network Diagnostics extension.

Features:
* Add `az aks net-diagnostics` command for comprehensive read-only AKS network analysis
* DNS diagnostics: VNET DNS configuration and private DNS zone validation
* Outbound connectivity analysis: Internet egress and connectivity to required endpoints
* Network Security Group (NSG) analysis: Rule validation and recommendations
* Route table analysis: Custom routes and next hop validation
* Private DNS zone validation for private AKS clusters
* Private Link and Private Endpoint analysis
* JSON report export with `--json-report` option
* Detailed diagnostic output with `--details` flag
* Active connectivity tests from cluster nodes with `--probe-test` flag
* Runs using user's Azure CLI credentials with clear permission requirement messaging
* Severity levels: INFO, WARNING, ERROR, CRITICAL

Known Limitations:
* Preview release - APIs and command structure may change
* Requires Azure CLI 2.60.0 or later
* Read-only analysis only - does not modify any resources
* Some diagnostic checks may be skipped based on user permissions
* Active connectivity tests (`--probe-test`) require Virtual Machine Contributor permissions
