#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from codecs import open
from setuptools import setup, find_packages

try:
    from azext_aks_net_diagnostics._version import __version__
except ImportError:
    __version__ = "0.1.0b1"

VERSION = __version__

CLASSIFIERS = [
    'Development Status :: 4 - Beta',
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
DEPENDENCIES = []

with open('README.md', 'r', encoding='utf-8') as f:
    README = f.read()
with open('HISTORY.rst', 'r', encoding='utf-8') as f:
    HISTORY = f.read()

setup(
    name='aks-net-diagnostics',
    version=VERSION,
    description='Microsoft Azure Command-Line Tools AKS Network Diagnostics Extension',
    author='Microsoft Corporation',
    author_email='azpycli@microsoft.com',
    url='https://github.com/Azure/azure-cli-extensions/tree/main/src/aks-net-diagnostics',
    long_description=README + '\n\n' + HISTORY,
    long_description_content_type='text/markdown',
    license='MIT',
    classifiers=CLASSIFIERS,
    packages=find_packages(),
    install_requires=DEPENDENCIES,
    package_data={'azext_aks_net_diagnostics': ['azext_metadata.json']},
)
