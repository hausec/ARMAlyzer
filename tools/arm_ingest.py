import json
from typing import Optional
from pydantic import BaseModel, Field
from .arm_checks import Findings, check_vm_template

class IngestArgs(BaseModel):
    template_text: Optional[str] = Field(None, description="Contents of template.json")
    parameters_text: Optional[str] = Field(None, description="Contents of parameters.json")
    template_resource_uri: Optional[str] = None  # e.g., resource://local/template.json
    parameters_resource_uri: Optional[str] = None

def _read_resource(uri: str) -> str:
    # Implement with your SDK's resource reader if you wire one in; stdio-only can skip this.
    raise NotImplementedError("Resource reading not wired; pass raw text for now.")

def analyze_arm(args: IngestArgs) -> Findings:
    """
    Analyze Azure ARM/Bicep-exported template+parameters for common risks and misconfigurations.
    Returns structured findings.
    """
    if not (args.template_text and args.parameters_text):
        # For protos, require raw text; later you can support resource URIs.
        raise ValueError("Provide template_text and parameters_text")

    template = json.loads(args.template_text)
    parameters = json.loads(args.parameters_text)
    return check_vm_template(template, parameters)
