import json
import pathlib
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

class EntraFinding(BaseModel):
    id: str
    severity: str  # "low" | "med" | "high" | "critical"
    category: str  # "organization", "policies", "roles", "sync", "auth"
    resource: Optional[str] = None
    path: Optional[str] = None
    message: str
    recommendation: str

class EntraFindings(BaseModel):
    findings: List[EntraFinding]
    stats: Dict[str, int]
    summary: Dict[str, Any]

def analyze_entra_backup(backup_path: str) -> EntraFindings:
    """
    Analyze Entra ID backup files for security misconfigurations.
    
    Args:
        backup_path: Path to the EntraBackup directory
        
    Returns:
        EntraFindings object with security analysis results
    """
    findings: List[EntraFinding] = []
    backup_dir = pathlib.Path(backup_path)
    
    if not backup_dir.exists():
        raise ValueError(f"Backup directory not found: {backup_path}")
    
    # Analyze Organization settings
    findings.extend(_analyze_organization_settings(backup_dir))
    
    # Analyze Authorization Policies
    findings.extend(_analyze_authorization_policies(backup_dir))
    
    # Analyze Directory Roles and Members
    findings.extend(_analyze_directory_roles(backup_dir))
    
    # Analyze On-Premises Sync Settings
    findings.extend(_analyze_sync_settings(backup_dir))
    
    # Analyze Security Defaults
    findings.extend(_analyze_security_defaults(backup_dir))
    
    # Analyze Authentication Methods
    findings.extend(_analyze_auth_methods(backup_dir))
    
    # Calculate statistics
    stats = {
        "total": len(findings),
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "med": sum(1 for f in findings if f.severity == "med"),
        "low": sum(1 for f in findings if f.severity == "low"),
    }
    
    # Generate summary
    summary = _generate_summary(findings, backup_dir)
    
    return EntraFindings(findings=findings, stats=stats, summary=summary)

def _analyze_organization_settings(backup_dir: pathlib.Path) -> List[EntraFinding]:
    """Analyze organization-level security settings"""
    findings = []
    org_file = backup_dir / "Organization" / "Organization.json"
    
    if not org_file.exists():
        findings.append(EntraFinding(
            id="ORG-001",
            severity="high",
            category="organization",
            message="Organization.json not found in backup",
            recommendation="Ensure complete backup of organization settings"
        ))
        return findings
    
    try:
        with open(org_file, 'r', encoding='utf-8') as f:
            org_data = json.load(f)
        
        # Check for accidental deletion protection
        if not org_data.get("onPremisesSyncEnabled", False):
            findings.append(EntraFinding(
                id="ORG-002",
                severity="med",
                category="organization",
                message="On-premises sync is disabled - no accidental deletion protection",
                recommendation="Enable on-premises sync or implement alternative deletion protection"
            ))
        
        # Check technical notification emails
        tech_emails = org_data.get("technicalNotificationMails", [])
        if not tech_emails:
            findings.append(EntraFinding(
                id="ORG-003",
                severity="med",
                category="organization",
                message="No technical notification emails configured",
                recommendation="Configure technical notification emails for security alerts"
            ))
        
        # Check security compliance notification emails
        sec_emails = org_data.get("securityComplianceNotificationMails", [])
        if not sec_emails:
            findings.append(EntraFinding(
                id="ORG-004",
                severity="med",
                category="organization",
                message="No security compliance notification emails configured",
                recommendation="Configure security compliance notification emails"
            ))
        
        # Check tenant type
        tenant_type = org_data.get("tenantType", "")
        if tenant_type == "AAD":
            findings.append(EntraFinding(
                id="ORG-005",
                severity="low",
                category="organization",
                message="Using legacy Azure AD tenant type",
                recommendation="Consider migrating to Microsoft Entra ID for enhanced features"
            ))
        
    except Exception as e:
        findings.append(EntraFinding(
            id="ORG-006",
            severity="high",
            category="organization",
            message=f"Error reading organization settings: {str(e)}",
            recommendation="Verify organization.json file integrity"
        ))
    
    return findings

def _analyze_authorization_policies(backup_dir: pathlib.Path) -> List[EntraFinding]:
    """Analyze authorization policy settings"""
    findings = []
    auth_policy_file = backup_dir / "Policies" / "AuthorizationPolicy" / "authorizationPolicy" / "authorizationPolicy.json"
    
    if not auth_policy_file.exists():
        findings.append(EntraFinding(
            id="AUTH-001",
            severity="high",
            category="policies",
            message="Authorization policy not found in backup",
            recommendation="Ensure complete backup of authorization policies"
        ))
        return findings
    
    try:
        with open(auth_policy_file, 'r', encoding='utf-8') as f:
            auth_data = json.load(f)
        
        # Check guest invite settings
        allow_invites = auth_data.get("allowInvitesFrom", "")
        if allow_invites == "everyone":
            findings.append(EntraFinding(
                id="AUTH-002",
                severity="high",
                category="policies",
                message="Guest invitations allowed from everyone",
                recommendation="Restrict guest invitations to specific domains or disable"
            ))
        
        # Check email-based subscriptions
        if auth_data.get("allowedToSignUpEmailBasedSubscriptions", False):
            findings.append(EntraFinding(
                id="AUTH-003",
                severity="med",
                category="policies",
                message="Email-based subscriptions signup allowed",
                recommendation="Disable email-based subscription signup for better control"
            ))
        
        # Check self-service password reset
        if auth_data.get("allowedToUseSSPR", False):
            findings.append(EntraFinding(
                id="AUTH-004",
                severity="med",
                category="policies",
                message="Self-service password reset enabled",
                recommendation="Review SSPR settings and consider additional restrictions"
            ))
        
        # Check user consent for risky apps
        risky_apps_consent = auth_data.get("allowUserConsentForRiskyApps")
        if risky_apps_consent is None:
            findings.append(EntraFinding(
                id="AUTH-005",
                severity="med",
                category="policies",
                message="User consent for risky apps not explicitly configured",
                recommendation="Explicitly disable user consent for risky applications"
            ))
        
        # Check default user role permissions
        default_perms = auth_data.get("defaultUserRolePermissions", {})
        if default_perms.get("allowedToCreateApps", False):
            findings.append(EntraFinding(
                id="AUTH-006",
                severity="high",
                category="policies",
                message="Default users can create applications",
                recommendation="Restrict application creation to administrators only"
            ))
        
        if default_perms.get("allowedToCreateSecurityGroups", False):
            findings.append(EntraFinding(
                id="AUTH-007",
                severity="high",
                category="policies",
                message="Default users can create security groups",
                recommendation="Restrict security group creation to administrators"
            ))
        
        if default_perms.get("allowedToCreateTenants", False):
            findings.append(EntraFinding(
                id="AUTH-008",
                severity="critical",
                category="policies",
                message="Default users can create tenants",
                recommendation="Disable tenant creation for default users"
            ))
        
    except Exception as e:
        findings.append(EntraFinding(
            id="AUTH-009",
            severity="high",
            category="policies",
            message=f"Error reading authorization policy: {str(e)}",
            recommendation="Verify authorization policy file integrity"
        ))
    
    return findings

def _analyze_directory_roles(backup_dir: pathlib.Path) -> List[EntraFinding]:
    """Analyze directory roles and privileged users"""
    findings = []
    roles_dir = backup_dir / "DirectoryRoles"
    
    if not roles_dir.exists():
        findings.append(EntraFinding(
            id="ROLE-001",
            severity="high",
            category="roles",
            message="Directory roles not found in backup",
            recommendation="Ensure complete backup of directory roles"
        ))
        return findings
    
    privileged_users = []
    global_admins = []
    
    try:
        for role_dir in roles_dir.iterdir():
            if not role_dir.is_dir():
                continue
            
            role_file = role_dir / f"{role_dir.name}.json"
            if not role_file.exists():
                continue
            
            with open(role_file, 'r', encoding='utf-8') as f:
                role_data = json.load(f)
            
            role_name = role_data.get("displayName", "")
            
            # Check for Global Administrator role
            if "Global Administrator" in role_name or role_data.get("roleTemplateId") == "62e90394-69f5-4237-9190-012177145e10":
                members_dir = role_dir / "Members"
                if members_dir.exists():
                    for member_dir in members_dir.iterdir():
                        if member_dir.is_dir():
                            member_file = member_dir / f"{member_dir.name}.json"
                            if member_file.exists():
                                with open(member_file, 'r', encoding='utf-8') as f:
                                    member_data = json.load(f)
                                global_admins.append({
                                    "name": member_data.get("displayName", ""),
                                    "upn": member_data.get("userPrincipalName", "")
                                })
            
            # Check for other privileged roles
            privileged_role_names = [
                "Privileged Role Administrator",
                "Security Administrator", 
                "Application Administrator",
                "Cloud Application Administrator",
                "Exchange Administrator",
                "SharePoint Administrator"
            ]
            
            if any(priv_role in role_name for priv_role in privileged_role_names):
                members_dir = role_dir / "Members"
                if members_dir.exists():
                    for member_dir in members_dir.iterdir():
                        if member_dir.is_dir():
                            member_file = member_dir / f"{member_dir.name}.json"
                            if member_file.exists():
                                with open(member_file, 'r', encoding='utf-8') as f:
                                    member_data = json.load(f)
                                privileged_users.append({
                                    "name": member_data.get("displayName", ""),
                                    "upn": member_data.get("userPrincipalName", ""),
                                    "role": role_name
                                })
        
        # Analyze findings
        if len(global_admins) > 5:
            findings.append(EntraFinding(
                id="ROLE-002",
                severity="high",
                category="roles",
                message=f"Too many Global Administrators ({len(global_admins)})",
                recommendation="Reduce Global Administrator count to minimum required (2-3 users)"
            ))
        
        if len(global_admins) == 0:
            findings.append(EntraFinding(
                id="ROLE-003",
                severity="critical",
                category="roles",
                message="No Global Administrators found",
                recommendation="Ensure at least one Global Administrator exists"
            ))
        
        if len(privileged_users) > 20:
            findings.append(EntraFinding(
                id="ROLE-004",
                severity="med",
                category="roles",
                message=f"High number of privileged users ({len(privileged_users)})",
                recommendation="Review privileged user assignments and implement PIM"
            ))
        
    except Exception as e:
        findings.append(EntraFinding(
            id="ROLE-005",
            severity="high",
            category="roles",
            message=f"Error analyzing directory roles: {str(e)}",
            recommendation="Verify directory roles backup integrity"
        ))
    
    return findings

def _analyze_sync_settings(backup_dir: pathlib.Path) -> List[EntraFinding]:
    """Analyze on-premises synchronization settings"""
    findings = []
    sync_file = backup_dir / "Directory" / "OnPremisesSynchronization.json"
    
    if not sync_file.exists():
        return findings  # Not applicable if no sync
    
    try:
        with open(sync_file, 'r', encoding='utf-8') as f:
            sync_data = json.load(f)
        
        features = sync_data.get("features", {})
        config = sync_data.get("configuration", {})
        
        # Check accidental deletion prevention
        acc_del_prevention = config.get("accidentalDeletionPrevention", {})
        if acc_del_prevention.get("synchronizationPreventionType") != "enabledForCount":
            findings.append(EntraFinding(
                id="SYNC-001",
                severity="high",
                category="sync",
                message="Accidental deletion prevention not properly configured",
                recommendation="Enable accidental deletion prevention with appropriate threshold"
            ))
        
        # Check password writeback
        if not features.get("passwordWritebackEnabled", False):
            findings.append(EntraFinding(
                id="SYNC-002",
                severity="med",
                category="sync",
                message="Password writeback is disabled",
                recommendation="Enable password writeback for better user experience"
            ))
        
        # Check user writeback
        if not features.get("userWritebackEnabled", False):
            findings.append(EntraFinding(
                id="SYNC-003",
                severity="low",
                category="sync",
                message="User writeback is disabled",
                recommendation="Consider enabling user writeback if using Exchange hybrid"
            ))
        
        # Check group writeback
        if not features.get("groupWriteBackEnabled", False):
            findings.append(EntraFinding(
                id="SYNC-004",
                severity="low",
                category="sync",
                message="Group writeback is disabled",
                recommendation="Consider enabling group writeback for Office 365 groups"
            ))
        
        # Check device writeback
        if not features.get("deviceWritebackEnabled", False):
            findings.append(EntraFinding(
                id="SYNC-005",
                severity="low",
                category="sync",
                message="Device writeback is disabled",
                recommendation="Consider enabling device writeback for device management"
            ))
        
    except Exception as e:
        findings.append(EntraFinding(
            id="SYNC-006",
            severity="high",
            category="sync",
            message=f"Error reading sync settings: {str(e)}",
            recommendation="Verify sync settings file integrity"
        ))
    
    return findings

def _analyze_security_defaults(backup_dir: pathlib.Path) -> List[EntraFinding]:
    """Analyze security defaults policy"""
    findings = []
    sec_defaults_file = backup_dir / "Policies" / "IdentitySecurityDefaultsEnforcementPolicy" / "00000000-0000-0000-0000-000000000005" / "00000000-0000-0000-0000-000000000005.json"
    
    if not sec_defaults_file.exists():
        findings.append(EntraFinding(
            id="SEC-001",
            severity="high",
            category="policies",
            message="Security defaults policy not found",
            recommendation="Enable security defaults or implement equivalent Conditional Access policies"
        ))
        return findings
    
    try:
        with open(sec_defaults_file, 'r', encoding='utf-8') as f:
            sec_data = json.load(f)
        
        if not sec_data.get("isEnabled", False):
            findings.append(EntraFinding(
                id="SEC-002",
                severity="critical",
                category="policies",
                message="Security defaults are disabled",
                recommendation="Enable security defaults or implement equivalent Conditional Access policies"
            ))
        
    except Exception as e:
        findings.append(EntraFinding(
            id="SEC-003",
            severity="high",
            category="policies",
            message=f"Error reading security defaults: {str(e)}",
            recommendation="Verify security defaults file integrity"
        ))
    
    return findings

def _analyze_auth_methods(backup_dir: pathlib.Path) -> List[EntraFinding]:
    """Analyze authentication methods policy"""
    findings = []
    auth_methods_dir = backup_dir / "Policies" / "AuthenticationMethodsPolicy" / "AuthenticationMethodConfigurations"
    
    if not auth_methods_dir.exists():
        return findings
    
    try:
        # Check for weak authentication methods
        weak_methods = ["SMS", "Voice"]
        
        for method in weak_methods:
            method_file = auth_methods_dir / f"{method}.json"
            if method_file.exists():
                with open(method_file, 'r', encoding='utf-8') as f:
                    method_data = json.load(f)
                
                if method_data.get("state") == "enabled":
                    findings.append(EntraFinding(
                        id=f"AUTH-METHOD-{method}",
                        severity="med",
                        category="auth",
                        message=f"{method} authentication method is enabled",
                        recommendation=f"Consider disabling {method} authentication in favor of stronger methods"
                    ))
        
        # Check for strong authentication methods
        strong_methods = ["FIDO2", "MicrosoftAuthenticator"]
        
        for method in strong_methods:
            method_file = auth_methods_dir / f"{method}.json"
            if method_file.exists():
                with open(method_file, 'r', encoding='utf-8') as f:
                    method_data = json.load(f)
                
                if method_data.get("state") != "enabled":
                    findings.append(EntraFinding(
                        id=f"AUTH-METHOD-{method}",
                        severity="med",
                        category="auth",
                        message=f"{method} authentication method is disabled",
                        recommendation=f"Enable {method} authentication for stronger security"
                    ))
        
    except Exception as e:
        findings.append(EntraFinding(
            id="AUTH-METHOD-ERROR",
            severity="high",
            category="auth",
            message=f"Error reading authentication methods: {str(e)}",
            recommendation="Verify authentication methods policy files"
        ))
    
    return findings

def _generate_summary(findings: List[EntraFinding], backup_dir: pathlib.Path) -> Dict[str, Any]:
    """Generate summary of the analysis"""
    summary = {
        "backup_path": str(backup_dir),
        "analysis_date": pathlib.Path().cwd().stat().st_mtime,
        "critical_issues": [f for f in findings if f.severity == "critical"],
        "high_issues": [f for f in findings if f.severity == "high"],
        "categories": {}
    }
    
    # Group by category
    for finding in findings:
        category = finding.category
        if category not in summary["categories"]:
            summary["categories"][category] = []
        summary["categories"][category].append(finding.id)
    
    return summary
