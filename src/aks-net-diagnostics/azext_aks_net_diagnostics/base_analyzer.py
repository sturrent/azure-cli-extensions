# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
Base class for analyzers

Provides common functionality for all network diagnostic analyzers.
Uses pre-authenticated Azure SDK clients from Azure CLI.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from .models import Finding


class BaseAnalyzer(ABC):
    """Base class for all analyzers"""

    def __init__(self, clients: Dict[str, Any], cluster_info: Dict[str, Any], logger=None):
        """
        Initialize analyzer

        Args:
            clients: Dictionary of pre-authenticated Azure SDK clients
                     (aks_client, network_client, compute_client, privatedns_client)
            cluster_info: AKS cluster information
            logger: Optional logger instance (uses standard logging if not provided)
        """
        self.clients = clients
        self.cluster_info = cluster_info
        if logger is not None:
            self.logger = logger
        else:
            self.logger = logging.getLogger(f"aks_net_diagnostics.{self.__class__.__name__}")
        self.findings: List[Finding] = []

    @abstractmethod
    def analyze(self) -> Dict[str, Any]:
        """
        Perform analysis

        Returns:
            Analysis results as dictionary
        """
        raise NotImplementedError("Subclasses must implement analyze() method")

    def add_finding(self, finding: Finding):
        """Add a finding to the results"""
        self.findings.append(finding)
        # Map severity to appropriate log level
        # Add 2-space indentation to match other diagnostic messages
        if finding.severity.value in ["critical", "error"]:
            self.logger.error("  %s", finding.message)
        elif finding.severity.value == "warning":
            self.logger.warning("  %s", finding.message)
        else:
            self.logger.info("  %s", finding.message)

    def get_findings(self) -> List[Finding]:
        """Get all findings from this analyzer"""
        return self.findings

    def get_cluster_property(self, *keys: str, default: Any = None) -> Any:
        """
        Safely get nested property from cluster info

        Args:
            *keys: Nested keys to traverse
            default: Default value if key not found

        Returns:
            Value at the specified path or default
        """
        result = self.cluster_info
        for key in keys:
            if isinstance(result, dict):
                result = result.get(key)
            else:
                return default
            if result is None:
                return default
        return result
