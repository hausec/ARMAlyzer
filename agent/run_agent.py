import json, pathlib, sys
from pydantic import BaseModel
from pydantic_ai import Agent

# Add parent directory to path for imports
sys.path.append(str(pathlib.Path(__file__).parent.parent))

# ---- Client ↔ MCP glue depends on your client runtime. Here we'll just call the tool code directly.
# In production you'd let your MCP client host the tool and the agent call via MCP.
from tools.arm_ingest import analyze_arm, IngestArgs
from tools.entra_analyzer import analyze_entra_backup

SYSTEM_PROMPT = """
You are a cloud security analyst specializing in Azure security. You can analyze:

1. ARM Templates: When given ARM template and parameters files, analyze for infrastructure security issues
2. Entra ID Configurations: When given Entra ID backup files, analyze for identity security issues

For ARM Templates:
- Call `analyze_arm` with template and parameteDrs
- Focus on infrastructure security: image versions, credentials, identities, networking

For Entra ID Analysis:
- Call `analyze_entra` with backup path
- Focus on identity security: policies, roles, authentication, sync settings

Always:
- Summarize key risks (highest severity first)
- Explain why each finding matters
- Provide concrete remediation steps
- Output executive summary followed by detailed findings
"""

class Report(BaseModel):
    analysis_type: str  # "arm" or "entra"
    summary: str
    table_md: str
    recommendations: str

def render_arm_report(findings) -> Report:
    sev_order = {"high": 0, "med": 1, "low": 2}
    sorted_findings = sorted(findings.findings, key=lambda x: sev_order[x.severity])
    lines = ["| Severity | ID | Resource | Message |", "|---|---|---|---|"]
    for f in sorted_findings:
        lines.append(f"| {f.severity} | {f.id} | {f.resource or ''} | {f.message} |")
    summary = f"{findings.stats['total']} ARM template findings " \
              f"({findings.stats['high']} high / {findings.stats['med']} med / {findings.stats['low']} low)."
    return Report(
        analysis_type="arm",
        summary=summary, 
        table_md="\n".join(lines),
        recommendations="Review ARM template security configurations and implement recommended changes."
    )

def render_entra_report(findings) -> Report:
    sev_order = {"critical": 0, "high": 1, "med": 2, "low": 3}
    sorted_findings = sorted(findings.findings, key=lambda x: sev_order[x.severity])
    lines = ["| Severity | ID | Category | Message |", "|---|---|---|---|"]
    for f in sorted_findings:
        lines.append(f"| {f.severity} | {f.id} | {f.category} | {f.message} |")
    summary = f"{findings.stats['total']} Entra ID findings " \
              f"({findings.stats['critical']} critical / {findings.stats['high']} high / {findings.stats['med']} med / {findings.stats['low']} low)."
    return Report(
        analysis_type="entra",
        summary=summary,
        table_md="\n".join(lines),
        recommendations="Review Entra ID security policies and implement recommended changes."
    )

async def analyze_arm_with_agent(template_path: str, params_path: str):
    """Use pydantic-ai agent to analyze ARM templates"""
    import os
    
    # Check if API key is set
    if not os.getenv('OPENAI_API_KEY'):
        raise ValueError("OPENAI_API_KEY environment variable is not set. Please set it to use the LLM agent.")
    
    # Create agent with a simple model (you can configure this with your preferred LLM)
    agent = Agent('openai:gpt-4o-mini', result_type=Report, system_prompt=SYSTEM_PROMPT)
    
    # Read files
    t_text = pathlib.Path(template_path).read_text(encoding="utf-8")
    p_text = pathlib.Path(params_path).read_text(encoding="utf-8")
    
    # Analyze using the tool
    findings = analyze_arm(IngestArgs(template_text=t_text, parameters_text=p_text))
    
    # Use agent to generate report
    prompt = f"""
    Analyze these ARM template findings and create a comprehensive security report:
    
    Findings: {findings.model_dump_json()}
    
    Focus on:
    1. Infrastructure security risks
    2. Credential management issues
    3. Identity and access management
    4. Network security configurations
    
    Provide actionable remediation steps for each critical finding.
    """
    
    result = await agent.run_sync(prompt)
    return result.data

async def analyze_entra_with_agent(backup_path: str):
    """Use pydantic-ai agent to analyze Entra ID configurations"""
    import os
    
    # Check if API key is set
    if not os.getenv('OPENAI_API_KEY'):
        raise ValueError("OPENAI_API_KEY environment variable is not set. Please set it to use the LLM agent.")
    
    # Create agent with a simple model (you can configure this with your preferred LLM)
    agent = Agent('openai:gpt-4o-mini', result_type=Report, system_prompt=SYSTEM_PROMPT)
    
    # Analyze using the tool
    findings = analyze_entra_backup(backup_path)
    
    # Use agent to generate report
    prompt = f"""
    Analyze these Entra ID security findings and create a comprehensive security report:
    
    Findings: {findings.model_dump_json()}
    
    Focus on:
    1. Identity and access management risks
    2. Authentication and authorization policies
    3. Privileged access management
    4. Directory synchronization security
    
    Prioritize critical and high-severity findings. Provide specific remediation steps
    for policy changes, role assignments, and security configurations.
    """
    
    result = await agent.run_sync(prompt)
    return result.data

def main_arm(template_path: str, params_path: str):
    """Analyze ARM templates"""
    print(f"Analyzing ARM template: {template_path}")
    print(f"Parameters file: {params_path}")
    print("=" * 60)
    
    t_text = pathlib.Path(template_path).read_text(encoding="utf-8")
    p_text = pathlib.Path(params_path).read_text(encoding="utf-8")

    # In a full MCP flow: the Agent would choose a tool call. For a local demo, we invoke it directly:
    findings = analyze_arm(IngestArgs(template_text=t_text, parameters_text=p_text))

    # Print summary
    print(f"\nANALYSIS SUMMARY")
    print(f"Total findings: {findings.stats['total']}")
    print(f"High: {findings.stats['high']} | Medium: {findings.stats['med']} | Low: {findings.stats['low']}")
    
    # Print findings by severity
    severity_order = ["high", "med", "low"]
    for severity in severity_order:
        severity_findings = [f for f in findings.findings if f.severity == severity]
        if severity_findings:
            print(f"\n{severity.upper()} SEVERITY ISSUES:")
            for finding in severity_findings:
                print(f"  - {finding.id}: {finding.message}")
                print(f"    Resource: {finding.resource or 'N/A'}")
                print()
    
    print(f"\nAnalysis complete!")

def main_entra(backup_path: str):
    """Analyze Entra ID backup"""
    findings = analyze_entra_backup(backup_path)
    
    print(f"Analyzing Entra ID backup: {backup_path}")
    print("=" * 60)
    
    # Print summary
    print(f"\nANALYSIS SUMMARY")
    print(f"Total findings: {findings.stats['total']}")
    print(f"Critical: {findings.stats['critical']} | High: {findings.stats['high']} | Medium: {findings.stats['med']} | Low: {findings.stats['low']}")
    
    # Print findings by severity
    severity_order = ["critical", "high", "med", "low"]
    for severity in severity_order:
        severity_findings = [f for f in findings.findings if f.severity == severity]
        if severity_findings:
            print(f"\n{severity.upper()} SEVERITY ISSUES:")
            for finding in severity_findings:
                print(f"  - {finding.id}: {finding.message}")
                print(f"    Recommendation: {finding.recommendation}")
                print()
    
    # Print category breakdown
    if findings.summary.get("categories"):
        print(f"\nISSUES BY CATEGORY:")
        for category, issue_ids in findings.summary["categories"].items():
            print(f"  {category}: {len(issue_ids)} issues")
    
    print(f"\nAnalysis complete!")

def main():
    """Main function with argument parsing"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  ARM Analysis: python agent/run_agent.py arm <template.json> <parameters.json>")
        print("  Entra Analysis: python agent/run_agent.py entra <backup_path>")
        print("\nExamples:")
        print("  python agent/run_agent.py arm fixtures/template.json fixtures/parameters.json")
        print("  python agent/run_agent.py entra c:/EntraBackup")
        sys.exit(1)
    
    analysis_type = sys.argv[1].lower()
    
    if analysis_type == "arm":
        if len(sys.argv) != 4:
            print("ARM analysis requires template and parameters files")
            print("Usage: python agent/run_agent.py arm <template.json> <parameters.json>")
            sys.exit(1)
        main_arm(sys.argv[2], sys.argv[3])
    elif analysis_type == "entra":
        if len(sys.argv) != 3:
            print("Entra analysis requires backup path")
            print("Usage: python agent/run_agent.py entra <backup_path>")
            sys.exit(1)
        main_entra(sys.argv[2])
    else:
        print(f"Unknown analysis type: {analysis_type}")
        print("Supported types: arm, entra")
        sys.exit(1)

if __name__ == "__main__":
    main()
