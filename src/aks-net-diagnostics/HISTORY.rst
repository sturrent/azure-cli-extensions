Release History
===============

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
