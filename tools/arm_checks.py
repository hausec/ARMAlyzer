from typing import List, Optional, Dict, Any
from pydantic import BaseModel

class Finding(BaseModel):
    id: str
    severity: str  # "low" | "med" | "high"
    resource: Optional[str] = None
    path: Optional[str] = None
    message: str

class Findings(BaseModel):
    findings: List[Finding]
    stats: Dict[str, int]

def check_vm_template(template: Dict[str, Any], parameters: Dict[str, Any]) -> Findings:
    f: List[Finding] = []
    res = template.get("resources", [])
    # 1) image pinned?
    for r in res:
        if r.get("type", "").lower() == "microsoft.compute/virtualmachines":
            name = r.get("name")
            img = (r.get("properties", {})
                     .get("storageProfile", {})
                     .get("imageReference", {}))
            version = img.get("version")
            if version and version.lower() == "latest":
                f.append(Finding(
                    id="IMG-001",
                    severity="med",
                    resource=name,
                    path="resources[*].properties.storageProfile.imageReference.version",
                    message="Image version is 'latest'. Pin to a specific version to avoid drift."
                ))
            # 2) admin username hard-coded
            osprof = r.get("properties", {}).get("osProfile", {})
            if "adminUsername" in osprof:
                f.append(Finding(
                    id="OS-001",
                    severity="med",
                    resource=name,
                    path="resources[*].properties.osProfile.adminUsername",
                    message="Local admin username defined in template. Ensure password not hard-coded and use Azure VM extensions or secrets store."
                ))
            # 3) MI hygiene
            ident = r.get("identity", {})
            if ident:
                t = ident.get("type", "")
                user_ids = list((ident.get("userAssignedIdentities") or {}).keys())
                if "UserAssigned" in t and "SystemAssigned" in t and len(user_ids) >= 1:
                    f.append(Finding(
                        id="MI-001",
                        severity="med",
                        resource=name,
                        path="resources[*].identity",
                        message=f"VM has SystemAssigned + {len(user_ids)} UserAssigned identities. Review least-privilege, role scope, and blast radius."
                    ))

    # 4) parameters quality (nulls)
    null_params = []
    for k, v in (parameters.get("parameters") or {}).items():
        if isinstance(v, dict) and v.get("value", None) is None:
            null_params.append(k)
    if null_params:
        f.append(Finding(
            id="PAR-001",
            severity="low",
            resource=None,
            path="parameters.*.value",
            message=f"Parameters have null values: {', '.join(null_params)}. Provide CI defaults or validation."
        ))

    stats = {
        "total": len(f),
        "high": sum(1 for x in f if x.severity == "high"),
        "med": sum(1 for x in f if x.severity == "med"),
        "low": sum(1 for x in f if x.severity == "low"),
    }
    return Findings(findings=f, stats=stats)
