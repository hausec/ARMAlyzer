import json
from typing import Optional
from pydantic import BaseModel, Field
from .entra_analyzer import analyze_entra_backup, EntraFindings

class EntraAnalyzeArgs(BaseModel):
    backup_path: str = Field(..., description="Path to the EntraBackup directory")
    include_summary: Optional[bool] = Field(True, description="Include detailed summary in results")

def analyze_entra_backup_tool(args: EntraAnalyzeArgs) -> EntraFindings:
    """
    Analyze Entra ID backup files for security misconfigurations.
    
    This tool examines:
    - Organization settings (accidental deletion protection, notifications)
    - Authorization policies (guest access, user permissions)
    - Directory roles (privileged users, Global Admins)
    - Sync settings (password writeback, user writeback)
    - Security defaults (MFA enforcement)
    - Authentication methods (weak vs strong methods)
    
    Returns structured findings with severity levels and recommendations.
    """
    try:
        findings = analyze_entra_backup(args.backup_path)
        
        # If summary not requested, remove it to reduce response size
        if not args.include_summary:
            findings.summary = {}
        
        return findings
        
    except Exception as e:
        # Return error as a finding
        return EntraFindings(
            findings=[{
                "id": "ERROR-001",
                "severity": "critical",
                "category": "system",
                "message": f"Analysis failed: {str(e)}",
                "recommendation": "Check backup path and file integrity"
            }],
            stats={"total": 1, "critical": 1, "high": 0, "med": 0, "low": 0},
            summary={"error": str(e)}
        )
