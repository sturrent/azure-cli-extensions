# Contributing to AKS Network Diagnostics Extension

Thank you for your interest in contributing to the AKS Network Diagnostics extension!

## Development Setup

### Prerequisites

- Python 3.10 or later
- Azure CLI 2.60.0 or later
- azdev (Azure CLI development tools)

### Set Up Development Environment

1. **Install azdev**:
   ```bash
   python3 -m venv ~/.virtualenvs/azdev
   source ~/.virtualenvs/azdev/bin/activate
   pip install azdev
   ```

2. **Set up Azure CLI for development**:
   ```bash
   azdev setup -r ~/gitrepos/azure-cli-extensions
   ```

3. **Install the extension in development mode**:
   ```bash
   azdev extension add aks-net-diagnostics
   ```

## Making Changes

### Code Style

- Follow PEP 8 guidelines
- Use 4 spaces for indentation
- Maximum line length: 120 characters
- Use descriptive variable and function names

### Running Style Checks

Before submitting changes, run:

```bash
azdev style aks-net-diagnostics
azdev linter aks-net-diagnostics
```

### Testing

1. **Manual Testing**:
   ```bash
   az aks net-diagnostics --resource-group <rg> --name <cluster>
   ```

2. **Test with Different Options**:
   ```bash
   az aks net-diagnostics --resource-group <rg> --name <cluster> --details
   az aks net-diagnostics --resource-group <rg> --name <cluster> --probe-test
   az aks net-diagnostics --resource-group <rg> --name <cluster> --json-report test.json
   ```

### Adding New Analyzers

To add a new network analyzer:

1. Create a new analyzer class in `azext_aks_net_diagnostics/analyzers/`
2. Inherit from `BaseAnalyzer`
3. Implement the `analyze()` method
4. Register the analyzer in `orchestrator.py`

Example structure:
```python
from azext_aks_net_diagnostics.analyzers.base_analyzer import BaseAnalyzer
from azext_aks_net_diagnostics.models import DiagnosticResult, Severity

class NewAnalyzer(BaseAnalyzer):
    def __init__(self, cluster_data, clients):
        super().__init__("New Analyzer", cluster_data, clients)
    
    def analyze(self):
        # Your analysis logic here
        results = []
        # Add diagnostic results
        return results
```

## Submitting Changes

### Pull Request Process

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/<your-username>/azure-cli-extensions.git
   cd azure-cli-extensions
   ```

2. **Create a Branch**:
   ```bash
   git checkout -b feature/my-improvement
   ```

3. **Make Your Changes** and commit:
   ```bash
   git add .
   git commit -m "Description of changes"
   ```

4. **Run Validation**:
   ```bash
   azdev style aks-net-diagnostics
   azdev linter aks-net-diagnostics
   ```

5. **Push and Create PR**:
   ```bash
   git push origin feature/my-improvement
   ```

### PR Guidelines

- Provide clear description of changes
- Reference any related issues
- Include testing results
- Ensure all checks pass
- Update HISTORY.rst if adding features

## Code of Conduct

This project follows the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

## Questions?

For questions or discussions, please open an issue in the repository.

## License

All contributions are licensed under the MIT License.
