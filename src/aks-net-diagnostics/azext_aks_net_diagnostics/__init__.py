# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
AKS Network Diagnostics Module

This module provides comprehensive network diagnostics for Azure Kubernetes Service (AKS) clusters.
"""

from ._version import __version__
from .orchestrator import run_diagnostics

__all__ = ["run_diagnostics", "__version__"]
