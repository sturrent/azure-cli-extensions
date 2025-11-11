# Quick Reference - Next Steps

## Current Location
```bash
cd /home/sturrent/gitrepos/azure-cli-extensions
```

## Files Ready
- ✅ `EXTENSION-CONVERSION-PLAN.md` - Complete migration plan with all templates
- ✅ `PROGRESS-SUMMARY.md` - Current progress and status
- ✅ `src/aks-net-diagnostics/azext_aks_net_diagnostics/` - All 17 diagnostic modules copied

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
