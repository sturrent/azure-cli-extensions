Release History
===============

0.1.0b1 (2025-01-XX)
++++++++++++++++++++

**Initial Preview Release**

This is the first beta release of the AKS Network Diagnostics extension.

Features:
* Add `az aks net-diagnostics` command for comprehensive AKS network analysis
* DNS diagnostics: CoreDNS configuration and resolution testing
* Outbound connectivity analysis: Internet egress and firewall rule validation
* Load balancer diagnostics: Health probe configuration and testing
* Network Security Group (NSG) analysis: Rule validation and recommendations
* Route table analysis: Custom routes and next hop validation
* Private DNS zone validation for private AKS clusters
* Private Link and Private Endpoint analysis
* JSON report export with `--json-report` option
* Detailed diagnostic output with `--details` flag
* Health probe testing with `--probe-test` flag

Known Limitations:
* Preview release - APIs and command structure may change
* Requires Azure CLI 2.60.0 or later
* Some advanced networking scenarios may not be fully covered
* Health probe testing requires appropriate network access

Future Releases:
* Enhanced diagnostics for Azure CNI Overlay and Azure CNI Powered by Cilium
* Support for multi-cluster scenarios
* Integration with Azure Monitor diagnostics
* Automated remediation suggestions
* Performance optimization for large clusters
* Additional analyzer modules for specialized scenarios
