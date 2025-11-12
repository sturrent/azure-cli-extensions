Release History
===============

0.2.0b1 (2025-11-12)
++++++++++++++++++++

**Feature Enhancements**

* **Output Format Support**: Added full support for Azure CLI output formats (`-o json`, `-o yaml`, `-o tsv`, `-o table`)
* Console report automatically suppressed when using non-table output formats
* Optimized JSON generation for better performance (generate once, reuse for file and output)
* Improved JSON structure with better key ordering (findings appear at end for easier visibility)
* **Code Cleanup**: Removed unused `failure_analysis` field from JSON output
* Updated documentation with output format usage examples

0.1.0b1 (2025-01-XX)
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
