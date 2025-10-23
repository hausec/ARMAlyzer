from mcp.server import FastMCP
import json
from tools.arm_checks import check_vm_template, Findings  # your checker
from tools.entra_ingest import analyze_entra_backup_tool, EntraAnalyzeArgs, EntraFindings

mcp = FastMCP("azure-arm-sec")

@mcp.tool()
def analyze_arm(template_text: str, parameters_text: str) -> Findings:
    """Analyze Azure ARM/Bicep template+parameters and return findings."""
    template = json.loads(template_text)
    parameters = json.loads(parameters_text)
    return check_vm_template(template, parameters)

@mcp.tool()
def analyze_entra(backup_path: str, include_summary: bool = True) -> EntraFindings:
    """Analyze Entra ID backup files for security misconfigurations."""
    args = EntraAnalyzeArgs(backup_path=backup_path, include_summary=include_summary)
    return analyze_entra_backup_tool(args)

if __name__ == "__main__":
    mcp.run()  # stdio (local dev)
