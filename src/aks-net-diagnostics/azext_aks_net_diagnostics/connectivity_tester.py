"""
Connectivity Tester for AKS clusters

Handles active connectivity probing from node instances (VMSS or VM) including:
- API server reachability testing
- DNS resolution validation
- Network connectivity checks
- Node command execution via Azure SDK (VMSS or VM run-command)
- Test result analysis
"""

# pylint: disable=too-many-instance-attributes

import ipaddress
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.compute.models import RunCommandInput


@dataclass
class VMSSInstance:
    """VMSS instance information for connectivity testing"""

    vmss_name: str
    instance_id: str
    computer_name: str
    provisioning_state: str


@dataclass
class VMInstance:
    """VM instance information for connectivity testing"""

    vm_name: str
    computer_name: str
    provisioning_state: str


# pylint: disable=too-few-public-methods
class ConnectivityTester:
    """Manages connectivity testing from AKS node instances (VMSS or VM)"""

    def __init__(
        self,
        cluster_info: Dict[str, Any],
        clients: Dict[str, Any],
        dns_analyzer=None,
        show_details: bool = False,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize Connectivity Tester

        Args:
            cluster_info: AKS cluster information dictionary
            clients: Dictionary containing compute_client and other Azure SDK clients
            dns_analyzer: Optional DNS analyzer for private DNS validation
            show_details: Whether to show detailed test output
            logger: Optional logger instance
        """
        self.cluster_info = cluster_info
        self.compute_client = clients.get("compute_client")
        self.dns_analyzer = dns_analyzer
        self.show_details = show_details
        self.logger = logger or logging.getLogger("aks_net_diagnostics.connectivity_tester")

        self.probe_results = {
            "enabled": False,
            "tests": [],
            "summary": {"total_tests": 0, "passed": 0, "failed": 0, "errors": 0},
        }

    def test_connectivity(self, enable_probes: bool = False) -> Dict[str, Any]:
        """
        Main entry point for connectivity testing

        Args:
            enable_probes: Whether to run active connectivity probes

        Returns:
            Dictionary containing probe results and summary
        """
        self.logger.info("Checking node outbound connectivity...")

        if not enable_probes:
            self.logger.info(
                "Node outbound connectivity probing disabled. Use --probe-test to enable active connectivity checks."
            )
            return self.probe_results

        # Check if cluster is stopped
        power_state = self.cluster_info.get("power_state", {})
        power_code = power_state.get("code", "Unknown") if isinstance(power_state, dict) else str(power_state)

        if power_code.lower() == "stopped":
            self.logger.warning(
                "  Connectivity tests skipped: Cluster is in stopped state. "
                "Start cluster with 'az aks start' to run connectivity tests."
            )
            self.probe_results = {
                "enabled": False,
                "skipped": True,
                "reason": "Cluster is stopped",
                "tests": [],
                "summary": {"total_tests": 0, "passed": 0, "failed": 0, "errors": 0},
            }
            return self.probe_results

        # Check if cluster has failed
        provisioning_state = self.cluster_info.get("provisioning_state", "")
        if provisioning_state.lower() == "failed":
            self.logger.info("Cluster is in failed state. Connectivity tests may not be reliable.")

        self.logger.info("Starting active connectivity probes from VMSS instances...")

        # Initialize probe results
        self.probe_results = {
            "enabled": True,
            "tests": [],
            "summary": {"total_tests": 0, "passed": 0, "failed": 0, "errors": 0},
        }

        # Get node instances for testing (VMSS or VM, limited to first available for performance)
        node_instances = self._list_ready_node_instances()
        if not node_instances:
            self.logger.info("No node instances found for connectivity testing")
            return self.probe_results

        # Run connectivity tests on only the first available node to avoid long execution times
        # in clusters with many node pools
        first_node = node_instances[0]
        total_node_count = len(node_instances)
        node_type = "VMSS" if isinstance(first_node, VMSSInstance) else "VM"
        node_name = first_node.vmss_name if isinstance(first_node, VMSSInstance) else first_node.vm_name

        if total_node_count > 1:
            self.logger.info(
                "Found %s node instance(s). Testing connectivity from the first one: %s (%s) "
                "(skipping %s others for performance)",
                total_node_count,
                node_name,
                node_type,
                total_node_count - 1,
            )
        else:
            self.logger.info(
                "Found %s node instance(s). Testing connectivity from: %s (%s)",
                total_node_count,
                node_name,
                node_type
            )

        self._run_node_connectivity_tests(first_node)

        return self.probe_results

    def _list_ready_node_instances(self) -> List:
        """Return one ready instance per VMSS or VM for connectivity probing."""
        instances: List = []
        mc_rg = self.cluster_info.get("node_resource_group", "")
        if not mc_rg:
            return instances

        try:
            # List VMSS using SDK
            vmss_list = list(self.compute_client.virtual_machine_scale_sets.list(mc_rg))
        except (ResourceNotFoundError, HttpResponseError) as exc:
            # Check if it's a permission error
            error_str = str(exc).lower()
            if "authorization" in error_str or "forbidden" in error_str or "permission" in error_str:
                self.logger.warning(
                    "  Connectivity tests skipped: Insufficient permissions to access MC_ resource group (%s). "
                    "Grant the 'Virtual Machine Contributor' role or a custom role with "
                    "'Microsoft.Compute/virtualMachineScaleSets/virtualmachines/runCommand/action' permission "
                    "on the MC_ resource group to run connectivity tests.",
                    mc_rg
                )
                # Mark that tests were skipped due to permissions
                self.probe_results["skipped"] = True
                self.probe_results["reason"] = "Insufficient permissions to access MC_ resource group"
                self.probe_results["mc_resource_group"] = mc_rg
            else:
                self.logger.info("Error listing VMSS in %s: %s", mc_rg, exc)
            vmss_list = []  # Continue to check for VMs

        # Collect VMSS instances
        for vmss in vmss_list:
            vmss_name = vmss.name
            if not vmss_name:
                continue

            try:
                # List VMSS instances using SDK
                vmss_nodes = list(self.compute_client.virtual_machine_scale_set_vms.list(mc_rg, vmss_name))
            except (ResourceNotFoundError, HttpResponseError) as exc:
                self.logger.info("Error listing VMSS instances for %s: %s", vmss_name, exc)
                continue

            # Find first running instance
            for node in vmss_nodes:
                prov_state = node.provisioning_state
                if prov_state and prov_state.lower() == "succeeded":
                    instance_id = node.instance_id
                    computer_name = node.os_profile.computer_name if node.os_profile else ""

                    if instance_id:
                        instances.append(
                            VMSSInstance(
                                vmss_name=vmss_name,
                                instance_id=instance_id,
                                computer_name=computer_name,
                                provisioning_state=prov_state,
                            )
                        )
                        break  # Only one instance per VMSS

        # If no VMSS instances found, try to collect VM instances (for VM node pools)
        if not instances:
            try:
                # List VMs using SDK
                vm_list = list(self.compute_client.virtual_machines.list(mc_rg))
            except (ResourceNotFoundError, HttpResponseError) as exc:
                error_str = str(exc).lower()
                if "authorization" in error_str or "forbidden" in error_str or "permission" in error_str:
                    if not self.probe_results.get("skipped"):  # Only log if not already logged for VMSS
                        self.logger.warning(
                            "  Connectivity tests skipped: Insufficient permissions to access MC_ resource group (%s). "
                            "Grant the 'Virtual Machine Contributor' role or a custom role with "
                            "'Microsoft.Compute/virtualMachines/runCommand/action' permission "
                            "on the MC_ resource group to run connectivity tests.",
                            mc_rg
                        )
                        self.probe_results["skipped"] = True
                        self.probe_results["reason"] = "Insufficient permissions to access MC_ resource group"
                        self.probe_results["mc_resource_group"] = mc_rg
                else:
                    self.logger.info("Error listing VMs in %s: %s", mc_rg, exc)
                return instances

            # Collect VM instances
            for vm in vm_list:
                vm_name = vm.name
                if not vm_name:
                    continue

                prov_state = vm.provisioning_state
                if prov_state and prov_state.lower() == "succeeded":
                    computer_name = vm.os_profile.computer_name if vm.os_profile else ""

                    instances.append(
                        VMInstance(
                            vm_name=vm_name,
                            computer_name=computer_name,
                            provisioning_state=prov_state,
                        )
                    )
                    break  # Only one VM needed for testing

        return instances

    def _run_node_connectivity_tests(self, node_instance):
        """Run comprehensive connectivity tests from a node instance (VMSS or VM)"""
        api_server_fqdn = self._get_api_server_fqdn()
        if not api_server_fqdn:
            self.logger.info("Cannot determine API server FQDN. Skipping connectivity tests.")
            return

        # Determine if this is a private cluster
        api_server_profile = self.cluster_info.get("api_server_access_profile") or {}
        is_private = api_server_profile.get("enable_private_cluster", False)

        # Define connectivity tests in order:
        # 1. MCR DNS first (internet connectivity prerequisite)
        # 2. MCR HTTPS (if MCR DNS succeeds)
        # 3. API Server DNS (cluster-specific prerequisite)
        # 4. API Server HTTPS (if API Server DNS succeeds)
        tests = [
            {
                "name": "MCR DNS Resolution",
                "description": "Resolve MCR (Microsoft Container Registry) FQDN to IP address",
                "command": "nslookup mcr.microsoft.com",
                "expected_keywords": ["mcr.microsoft.com"],
                "check_private_ip": False,
                "critical": False,
                "skip_group": None,  # No dependencies
            },
            {
                "name": "Internet Connectivity",
                "description": "Test outbound internet connectivity to MCR (Microsoft Container Registry)",
                "command": "curl -v --max-time 60 --insecure --proxy-insecure https://mcr.microsoft.com/v2/",
                "expected_keywords": ["200", "401", "unauthorized"],
                "critical": False,
                "skip_group": "MCR DNS Resolution",  # Depends on MCR DNS
            },
            {
                "name": "API Server DNS Resolution",
                "description": "Resolve API server FQDN to IP address",
                "command": f"nslookup {api_server_fqdn}",
                "expected_keywords": [api_server_fqdn],
                "check_private_ip": is_private,
                "critical": True,
                "skip_group": None,  # No dependencies
            },
            {
                "name": "API Server HTTPS Connectivity",
                "description": "Test HTTPS connection to API server",
                "command": f"curl -v -k --max-time 15 https://{api_server_fqdn}:443",
                "expected_keywords": ["200", "401", "403", "HTTP/"],  # Any HTTP response indicates connectivity
                "critical": True,
                "skip_group": "API Server DNS Resolution",  # Depends on API Server DNS
            },
        ]

        # Execute each test with dependency tracking
        failed_tests = set()  # Track which tests have failed to determine skip logic

        for test in tests:
            test_name = test["name"]
            skip_group = test.get("skip_group")

            # Check if this test should be skipped due to dependency failure
            if skip_group and skip_group in failed_tests:
                self.logger.info("  Test: %s - SKIPPED (%s failed)", test_name, skip_group)

                # Get node name and type
                if isinstance(node_instance, VMSSInstance):
                    node_name = node_instance.vmss_name
                    node_id = node_instance.instance_id
                else:  # VMInstance
                    node_name = node_instance.vm_name
                    node_id = None

                result = {
                    "test_name": test_name,
                    "description": test["description"],
                    "command": test["command"],
                    "node_name": node_name,
                    "node_id": node_id,
                    "computer_name": node_instance.computer_name,
                    "status": "skipped",
                    "stdout": "",
                    "stderr": "",
                    "exit_code": None,
                    "analysis": f"Skipped because {skip_group} failed",
                    "critical": test.get("critical", False),
                }
                self.probe_results["tests"].append(result)
                self.probe_results["summary"]["total_tests"] += 1
                self.probe_results["summary"]["errors"] += 1
                continue

            self.logger.warning("  Running test: %s", test_name)
            result = self._execute_node_test(node_instance, test)
            self.probe_results["tests"].append(result)

            # Track failed tests to determine skip logic for dependent tests
            if result["status"] == "failed":
                failed_tests.add(test_name)
                if "DNS" in test_name:
                    self.logger.warning("    %s failed - dependent connectivity tests will be skipped", test_name)

            # Log test results based on detail level
            # In detailed mode, show full JSON with compacted output
            if self.show_details:
                # Create a copy of result with compacted stdout/stderr for logging
                log_result = result.copy()
                if log_result.get("stdout"):
                    log_result["stdout"] = log_result["stdout"].replace("\n", "\\n")
                if log_result.get("stderr"):
                    log_result["stderr"] = log_result["stderr"].replace("\n", "\\n")
                self.logger.warning("    Test result: %s", json.dumps(log_result, indent=2))
            else:
                # In summary mode, show test result with status indicator
                if result["status"] == "passed":
                    self.logger.warning("    [PASSED] %s", test_name)
                elif result["status"] == "failed":
                    self.logger.warning("    [FAILED] %s - %s", test_name, result["analysis"])
                else:
                    self.logger.warning("    [ERROR] %s - %s", test_name, result["analysis"])

            # Update summary
            self.probe_results["summary"]["total_tests"] += 1
            if result["status"] == "passed":
                self.probe_results["summary"]["passed"] += 1
            elif result["status"] == "failed":
                self.probe_results["summary"]["failed"] += 1
            else:
                self.probe_results["summary"]["errors"] += 1

    def _get_api_server_fqdn(self) -> Optional[str]:
        """Extract API server FQDN from cluster configuration"""
        # Check for private FQDN first
        private_fqdn = self.cluster_info.get("private_fqdn")
        if private_fqdn:
            return private_fqdn

        # Fall back to public FQDN
        fqdn = self.cluster_info.get("fqdn")
        if fqdn:
            return fqdn

        # Try to extract from kubeconfig
        fqdn_from_config = self.cluster_info.get("az_profile", {}).get("kube_config", {}).get("server", "")
        if fqdn_from_config:
            # Extract hostname from URL
            match = re.search(r"https?://([^:/]+)", fqdn_from_config)
            if match:
                return match.group(1)

        return None

    def _execute_node_test(self, node_instance, test: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a connectivity test on a node instance (VMSS or VM)"""
        # Get node name and type
        if isinstance(node_instance, VMSSInstance):
            node_name = node_instance.vmss_name
            node_id = node_instance.instance_id
        else:  # VMInstance
            node_name = node_instance.vm_name
            node_id = None

        result = {
            "test_name": test["name"],
            "description": test.get("description", ""),
            "command": test["command"],
            "node_name": node_name,
            "node_id": node_id,
            "computer_name": node_instance.computer_name,
            "status": "error",
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "analysis": "",
            "critical": test.get("critical", False),
        }

        mc_rg = self.cluster_info.get("node_resource_group", "")
        if not mc_rg:
            result["analysis"] = "Cannot determine node resource group"
            return result

        try:
            # Execute command via SDK run-command
            run_command_params = RunCommandInput(command_id="RunShellScript", script=[test["command"]])

            if isinstance(node_instance, VMSSInstance):
                # VMSS instance - use VMSS run command
                async_operation = self.compute_client.virtual_machine_scale_set_vms.begin_run_command(
                    mc_rg, node_instance.vmss_name, node_instance.instance_id, run_command_params
                )
            else:
                # VM instance - use VM run command
                async_operation = self.compute_client.virtual_machines.begin_run_command(
                    mc_rg, node_instance.vm_name, run_command_params
                )

            # Wait for completion (with 300 second timeout)
            response = async_operation.result(timeout=300)

            # Convert response to dictionary with snake_case keys
            response_dict = self._to_dict(response) if response else None
            result = self._analyze_test_result(test, response_dict, result)

        except (ResourceNotFoundError, HttpResponseError) as e:
            error_str = str(e)
            # Check if it's a permission error for runCommand
            if ("AuthorizationFailed" in error_str and
                    "runCommand/action" in error_str):
                result["analysis"] = (
                    "Unable to run connectivity test: Insufficient permissions. "
                    "The 'Virtual Machine Contributor' role or "
                    "'Microsoft.Compute/virtualMachines/runCommand/action' or "
                    "'Microsoft.Compute/virtualMachineScaleSets/virtualmachines/runCommand/action' "
                    "permission is required on the MC_ resource group to execute connectivity tests."
                )
                # Track that we have a permission error
                if "permission_error" not in self.probe_results:
                    self.probe_results["permission_error"] = True
                    self.probe_results["permission_error_reason"] = result["analysis"]
            else:
                result["analysis"] = f"Error executing test: {error_str}"
            result["status"] = "error"
            self.logger.debug("Test '%s' SDK error: %s", test["name"], e)
        except Exception as e:  # pylint: disable=broad-except
            result["analysis"] = f"Error executing test: {str(e)}"
            result["status"] = "error"
            self.logger.debug("Test '%s' error: %s", test["name"], e)

        return result

    def _analyze_test_result(self, test: Dict[str, Any], response: Any, result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the result of a connectivity test"""
        if not response or not isinstance(response, dict):
            result["analysis"] = "No valid response from VMSS command"
            result["status"] = "error"
            return result

        # Parse response
        parsed = self._parse_vmss_message(response)
        result["stdout"] = parsed["stdout"]
        result["stderr"] = parsed["stderr"]
        result["exit_code"] = parsed["exit_code"]

        # Check for curl errors in stderr even if exit code is 0
        curl_error_patterns = [
            r"curl: \(\d+\)",  # curl: (35), curl: (7), etc.
            r"error:\w+:",  # error:0A000126:SSL routines::...
            r"Failed to connect",
            r"Connection refused",
            r"Connection timed out",
            r"Could not resolve host",
        ]

        if result["stderr"]:
            for pattern in curl_error_patterns:
                if re.search(pattern, result["stderr"], re.IGNORECASE):
                    # Extract the error message for better analysis
                    curl_error_match = re.search(r"curl: \((\d+)\) (.+?)(?:\\n|$)", result["stderr"])
                    if curl_error_match:
                        error_code = curl_error_match.group(1)
                        error_msg = curl_error_match.group(2)
                        result["analysis"] = f"curl error ({error_code}): {error_msg}"
                    else:
                        # Look for SSL/TLS errors
                        ssl_error_match = re.search(r"(error:\w+:[^\\]+)", result["stderr"])
                        if ssl_error_match:
                            result["analysis"] = f"Connection failed: {ssl_error_match.group(1)}"
                        else:
                            result["analysis"] = "Connection failed with curl error"
                    result["status"] = "failed"
                    return result

        # Analyze result based on exit code
        if parsed["exit_code"] == 0:
            # Check for expected output
            expected_keywords = test.get("expected_keywords", [])
            if self._check_expected_output_combined(test, parsed["stdout"], parsed["stderr"], expected_keywords):
                # For DNS tests on private clusters, validate private IP
                if test.get("check_private_ip") and "DNS" in test["name"]:
                    api_server_fqdn = self._get_api_server_fqdn()
                    if self._validate_private_dns_resolution(parsed["stdout"], api_server_fqdn):
                        result["status"] = "passed"
                        result["analysis"] = "DNS resolved to private IP address"
                    else:
                        result["status"] = "failed"
                        result["analysis"] = "DNS did not resolve to private IP address (expected for private cluster)"
                else:
                    result["status"] = "passed"
                    result["analysis"] = "Test completed successfully"
            else:
                result["status"] = "failed"
                result["analysis"] = f"Expected output not found. Looking for: {', '.join(expected_keywords)}"
        else:
            result["status"] = "failed"
            result["analysis"] = f"Command failed with exit code {parsed['exit_code']}"

        return result

    def _parse_vmss_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VMSS run-command response message"""
        stdout = ""
        stderr = ""
        exit_code = -1

        try:
            # Extract value array from response
            value = message.get("value", [])
            if not isinstance(value, list):
                return {"stdout": stdout, "stderr": stderr, "exit_code": exit_code}

            for item in value:
                if not isinstance(item, dict):
                    continue

                code = item.get("code", "")
                msg = item.get("message", "")

                # Handle new format: ProvisioningState/succeeded with embedded stdout/stderr
                if code.startswith("ProvisioningState/"):
                    # Parse embedded stdout/stderr from message
                    stdout_match = re.search(r"\[stdout\]\n(.*?)(?:\[stderr\]|$)", msg, re.DOTALL)
                    stderr_match = re.search(r"\[stderr\]\n(.*?)$", msg, re.DOTALL)

                    if stdout_match:
                        stdout = stdout_match.group(1).strip()
                    if stderr_match:
                        stderr = stderr_match.group(1).strip()

                    # Check for exit code in message
                    if "exitcode" in msg.lower():
                        match = re.search(r'exitCode["\s:]+(\d+)', msg, re.IGNORECASE)
                        if match:
                            exit_code = int(match.group(1))

                    # If succeeded and no explicit exit code, assume 0
                    if "/succeeded" in code.lower() and exit_code == -1:
                        exit_code = 0
                    elif "/failed" in code.lower() and exit_code == -1:
                        exit_code = 1

                # Handle old format: ComponentStatus codes
                elif code == "ComponentStatus/StdOut/succeeded":
                    stdout = msg
                elif code == "ComponentStatus/StdErr/succeeded":
                    stderr = msg
                elif "exitcode" in msg.lower():
                    # Try to extract exit code from message
                    match = re.search(r'exitCode["\s:]+(\d+)', msg, re.IGNORECASE)
                    if match:
                        exit_code = int(match.group(1))

            # If exit code not found but we have stdout, assume success
            if exit_code == -1 and stdout:
                exit_code = 0

        except Exception as e:  # pylint: disable=broad-except
            self.logger.debug("Error parsing VMSS message: %s", e)

        return {"stdout": stdout, "stderr": stderr, "exit_code": exit_code}

    def _check_expected_output_combined(
        self, test: Dict[str, Any], stdout: str, stderr: str, expected_keywords: List[str]
    ) -> bool:
        """Check if output contains expected keywords, looking in both stdout and stderr for HTTP tests"""
        if not expected_keywords:
            return True  # No specific expectations

        # For HTTP connectivity tests, curl -v puts connection info in stderr
        test_name = test.get("name", "").lower()
        if "http" in test_name or "connectivity" in test_name:
            # Combine stdout and stderr for HTTP tests since curl -v uses stderr for connection details
            combined_output = f"{stdout}\n{stderr}".replace("\\n", "\n").lower()
            for keyword in expected_keywords:
                if keyword.lower() in combined_output:
                    return True
            return False

        # For other tests (like DNS), use only stdout
        return self._check_expected_output(stdout, expected_keywords)

    def _check_expected_output(self, output: str, expected_keywords: List[str]) -> bool:
        """Check if output contains expected keywords"""
        if not expected_keywords:
            return True

        output_lower = output.lower()
        for keyword in expected_keywords:
            if keyword.lower() in output_lower:
                return True

        return False

    # pylint: disable=too-many-return-statements
    def _validate_private_dns_resolution(self, nslookup_output: str, hostname: str) -> bool:
        """Validate that DNS resolution returns a private IP address for private clusters"""
        # Use the modular DNS analyzer if available
        if self.dns_analyzer and hasattr(self.dns_analyzer, "validate_private_dns_resolution"):
            return self.dns_analyzer.validate_private_dns_resolution(nslookup_output, hostname)

        # Fallback to inline validation if DNS analyzer not available
        try:
            # Convert compacted format back to regular format for parsing
            output_to_parse = nslookup_output.replace("\\n", "\n")

            # Check for DNS resolution failures first
            dns_error_patterns = [
                "nxdomain",
                "servfail",
                "refused",
                "can't find",
                "no servers could be reached",
                "communications error",
                "timed out",
            ]
            if any(error in output_to_parse.lower() for error in dns_error_patterns):
                return False  # DNS resolution failed completely

            # Parse nslookup output to extract IP addresses
            ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            found_ips = re.findall(ip_pattern, output_to_parse)

            if not found_ips:
                return False  # No IP addresses found

            # Filter out DNS server IPs more carefully
            lines = output_to_parse.split("\n")
            dns_server_ips = set()
            in_server_section = False

            for line in lines:
                line_lower = line.lower()
                if "server:" in line_lower:
                    in_server_section = True
                    server_ips = re.findall(ip_pattern, line)
                    dns_server_ips.update(server_ips)
                elif in_server_section and "address:" in line_lower:
                    server_ips = re.findall(ip_pattern, line)
                    dns_server_ips.update(server_ips)
                    in_server_section = False
                elif "non-authoritative answer" in line_lower or "name:" in line_lower:
                    in_server_section = False

            # Check resolved IPs (excluding DNS server IPs)
            resolved_ips = [ip for ip in found_ips if ip not in dns_server_ips]

            if not resolved_ips:
                return False  # Only DNS server IPs found, no actual resolution

            # Check if any of the resolved IPs are private
            for ip_str in resolved_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_private:
                        return True
                except ValueError:
                    continue

            return False

        except Exception as e:  # pylint: disable=broad-except
            self.logger.debug("Error validating private DNS resolution: %s", e)
            # If we can't parse the output, be conservative
            dns_error_patterns = [
                "nxdomain",
                "servfail",
                "refused",
                "can't find",
                "no servers could be reached",
                "communications error",
                "timed out",
            ]
            return not any(error in nslookup_output.lower() for error in dns_error_patterns)

    @staticmethod
    def _to_dict(obj: Any) -> Dict[str, Any]:
        """
        Convert Azure SDK object to dictionary with snake_case keys.

        Args:
            obj: Azure SDK object with as_dict() method

        Returns:
            Dictionary with snake_case keys
        """
        if not hasattr(obj, "as_dict"):
            return {}

        def to_snake_case(name: str) -> str:
            """Convert camelCase to snake_case"""
            s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
            return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()

        def convert_keys(data: Any) -> Any:
            """Recursively convert all keys to snake_case"""
            if isinstance(data, dict):
                return {to_snake_case(k): convert_keys(v) for k, v in data.items()}
            if isinstance(data, list):
                return [convert_keys(item) for item in data]
            return data

        return convert_keys(obj.as_dict())
