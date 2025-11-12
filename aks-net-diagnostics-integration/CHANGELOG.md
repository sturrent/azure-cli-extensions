# Changelog - AKS Net-Diagnostics Extension

This document tracks enhancements and improvements to the extension.

## v0.2.0b1 - November 12, 2025

### 🎨 Output Format Enhancements

**Added support for all Azure CLI output formats**

The extension now fully supports Azure CLI's standard output modes (`-o` / `--output`):

- **`table` (default)**: Human-readable console report with diagnostic findings
- **`json`**: Complete diagnostic data in JSON format
- **`yaml`**: Complete diagnostic data in YAML format  
- **`tsv`**: Tab-separated values for scripting and automation

#### Behavior Changes

- **Console Report Suppression**: When using `-o json`, `-o yaml`, or `-o tsv`, the formatted console report is automatically suppressed, returning only the structured data
- **Default Behavior**: Table format (default) continues to show the full console report as before
- **JSON File Export**: The `--json-report` flag works independently and can be combined with any output format

#### Implementation Details

- Output format detection: Automatically detects user's chosen format from Azure CLI context
- Console suppression: Skips console printing when non-table formats are selected
- Optimized JSON generation: Report data is generated once and reused for both file export and command output

#### Usage Examples

```bash
# Default table format - shows formatted console report
az aks net-diagnostics -g MyRG -n MyCluster

# JSON output - returns structured data only
az aks net-diagnostics -g MyRG -n MyCluster -o json

# YAML output - returns structured data in YAML
az aks net-diagnostics -g MyRG -n MyCluster -o yaml

# TSV output - returns flattened data for scripting
az aks net-diagnostics -g MyRG -n MyCluster -o tsv

# Save to file + JSON output to stdout
az aks net-diagnostics -g MyRG -n MyCluster -o json --json-report report.json

# Save to file + show console report
az aks net-diagnostics -g MyRG -n MyCluster --json-report report.json
```

#### Technical Changes

**Files Modified:**
- `custom.py`: Added output format detection and `suppress_console_output` parameter
- `orchestrator.py`: Added `suppress_console_output` parameter, optimized JSON generation
- `report_generator.py`: Updated to support console suppression

### 🧹 Code Cleanup

**Removed unused `failure_analysis` field**

The `failure_analysis` field that always contained `{"enabled": false}` has been removed from the codebase to reduce clutter and confusion.

#### What Was Removed

- Parameter from `ReportGenerator.__init__()`
- Field from JSON output structure
- All related assignments and documentation

#### Impact

- **JSON Output**: The `results` section now contains only `api_connectivity_probe` and `findings`
- **No Breaking Changes**: This field was never documented or used, removal is safe
- **Cleaner Output**: JSON structure is now more concise

#### Before
```json
{
  "results": {
    "api_connectivity_probe": {...},
    "failure_analysis": {"enabled": false},
    "findings": [...]
  }
}
```

#### After
```json
{
  "results": {
    "api_connectivity_probe": {...},
    "findings": [...]
  }
}
```

#### Technical Changes

**Files Modified:**
- `report_generator.py`: Removed parameter, assignment, and JSON field
- `orchestrator.py`: Removed argument from `ReportGenerator()` call

### 📊 JSON Structure Optimization

**Improved JSON key ordering for better readability**

Renamed JSON keys to ensure alphabetical sorting places findings at the end of the output, making it easier to locate diagnostic results.

#### Key Renamings

- `diagnostics` → `results`
- `networking` → `network_configuration`

#### Resulting Structure

When using `-o json` or `--json-report`, keys now appear in this order:

1. `cluster` - Cluster information
2. `metadata` - Diagnostic metadata  
3. `network_configuration` - Network analysis results
4. `results` - Diagnostic findings and probe results

This ensures that the most important section (`results` with `findings`) appears at the end where it's easily visible when scrolling through JSON output.

#### Technical Changes

**Files Modified:**
- `report_generator.py`: Updated `generate_json_report()` to use new key names

---

## Summary

These enhancements improve the extension's usability and integration with Azure CLI workflows:

✅ **Full output format support** enables better automation and scripting  
✅ **Code cleanup** removes confusing unused fields  
✅ **JSON optimization** improves readability of diagnostic results

All changes are backward-compatible with the initial v0.1.0b1 release, with the exception of the removed `failure_analysis` field (which was never documented or utilized).
