# Quick Reference - Next Steps

## ✅ Completed

### Phase 1: Repository Setup (COMPLETE)
- ✅ Forked and cloned `Azure/azure-cli-extensions`
- ✅ Created branch: `aks-net-diagnostics-extension`
- ✅ Directory structure created

### Phase 2: Code Migration & Extension Files (COMPLETE) ✅
- ✅ All 17 diagnostic modules copied and imports updated
- ✅ All 7 extension-specific files created with accurate descriptions
- ✅ All 3 documentation files created and verified for accuracy
- ✅ Documentation improvements: read-only disclaimer, permission handling, accurate feature descriptions
- ✅ Code quality: Flake8 + Pylint PASSED
- ✅ Extension installs successfully via `azdev extension add`
- ✅ Command working: `az aks net-diagnostics --help` (verified accurate help text)

### Phase 2.5: Development Environment (COMPLETE)
- ✅ Python venv at `~/.virtualenvs/azdev`
- ✅ azdev CLI installed (v0.2.8)
- ✅ Azure CLI 2.79.0 via azdev setup
- ✅ Azure SDK packages installed

---

## ⏳ Next: Phase 3 - Testing

### Test with Real AKS Cluster
```bash
cd /home/sturrent/gitrepos/azure-cli-extensions
```

## Files Ready
- ✅ `EXTENSION-CONVERSION-PLAN.md` - Complete migration plan with all templates
- ✅ `PROGRESS-SUMMARY.md` - Current progress and status
- ✅ `src/aks-net-diagnostics/azext_aks_net_diagnostics/` - All 17 diagnostic modules copied

## FIRST: Setup Development Environment (REQUIRED)

### Step 1: Create Python Virtual Environment
```bash
# Create a dedicated virtual environment for azdev
python3 -m venv ~/.virtualenvs/azdev
source ~/.virtualenvs/azdev/bin/activate
```

### Step 2: Install azdev CLI
```bash
# Install Azure CLI development tools
pip install azdev
```

### Step 3: Setup azdev with your extension
```bash
# Setup azdev pointing to your azure-cli-extensions fork
# This will install Azure CLI in editable mode and link your extension
azdev setup -r /home/sturrent/gitrepos/azure-cli-extensions -e aks-net-diagnostics
```

### Step 4: Verify Setup
```bash
# Check that Azure CLI and extension dev mode are working
az --version

# You should see your extension listed with a path indicating dev mode
```

**Why this is required:**
- ✅ Handles all Azure CLI core dependencies automatically
- ✅ Installs your extension in dev mode (changes immediately testable)
- ✅ Provides tools for linting, testing, and building
- ✅ No need to manually manage dependencies

---

## Next: Create 7 Extension Files

All templates are in `EXTENSION-CONVERSION-PLAN.md` section **"2. Files to Create (Extension-Specific)"**

### Files to Create:
1. `src/aks-net-diagnostics/setup.py`
2. `src/aks-net-diagnostics/azext_aks_net_diagnostics/__init__.py` (update existing)
3. `src/aks-net-diagnostics/azext_aks_net_diagnostics/commands.py`
4. `src/aks-net-diagnostics/azext_aks_net_diagnostics/_params.py`
5. `src/aks-net-diagnostics/azext_aks_net_diagnostics/custom.py`
6. `src/aks-net-diagnostics/azext_aks_net_diagnostics/_client_factory.py`
7. `src/aks-net-diagnostics/azext_aks_net_diagnostics/_help.py`

### Documentation Files:
8. `src/aks-net-diagnostics/README.md`
9. `src/aks-net-diagnostics/HISTORY.rst`
10. `src/aks-net-diagnostics/CONTRIBUTING.md` (optional)

## Quick Start Commands

```bash
# Open VS Code in the extension directory
code /home/sturrent/gitrepos/azure-cli-extensions

# Navigate to extension source
cd /home/sturrent/gitrepos/azure-cli-extensions/src/aks-net-diagnostics

# View current structure
tree azext_aks_net_diagnostics/

# After creating files, check status
git status
```

## Testing Commands (After Phase 3)

```bash
# Install azdev
pip install azdev

# Setup azdev
azdev setup -c /home/sturrent/gitrepos/azure-cli -r /home/sturrent/gitrepos/azure-cli-extensions

# Add extension in dev mode
azdev extension add aks-net-diagnostics

# Run linter
azdev linter aks-net-diagnostics

# Run style checks
azdev style aks-net-diagnostics

# Build wheel
azdev extension build aks-net-diagnostics
```

## Estimated Time Remaining
- Phase 2 completion (create files): **2-3 hours**
- Phase 3 (testing): **3-4 hours**
- Total to working extension: **5-7 hours**

---
**Open EXTENSION-CONVERSION-PLAN.md for detailed templates!**
