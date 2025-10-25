import json, pathlib, sys
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_evals import Dataset, Case
from pydantic_evals.evaluators import Contains, Equals, Evaluator, EvaluatorContext

# Add parent directory to path for imports
sys.path.append(str(pathlib.Path(__file__).parent.parent))

from tools.arm_ingest import analyze_arm, IngestArgs

SYSTEM_PROMPT = """
You are a cloud security analyst specializing in Azure security. You can analyze:

1. ARM Templates: When given ARM template and parameters files, analyze for infrastructure security issues
2. Entra ID Configurations: When given Entra ID backup files, analyze for identity security issues

For ARM Templates:
- Call `analyze_arm` with template and parameters
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

class VulnerabilityAnalysis(BaseModel):
    """Response model for vulnerability analysis"""
    highest_priority_vulnerability: str
    vulnerability_id: str
    severity: str
    explanation: str

class FieldContainsEvaluator(Evaluator):
    """Custom evaluator that checks if a specific field contains a value"""
    
    def __init__(self, field_name: str, expected_value: str, evaluation_name: str = None):
        self.field_name = field_name
        self.expected_value = expected_value
        self.evaluation_name = evaluation_name or f"field_{field_name}_contains"
    
    def evaluate(self, ctx: EvaluatorContext) -> bool:
        """Check if the specified field contains the expected value"""
        if hasattr(ctx.output, self.field_name):
            field_value = getattr(ctx.output, self.field_name)
            return self.expected_value.lower() in str(field_value).lower()
        return False

def create_arm_evaluation_dataset():
    """Create evaluation dataset for ARM template analysis"""
    
    # Read the test template and parameters
    template_path = pathlib.Path(__file__).parent.parent / "fixtures" / "template.json"
    params_path = pathlib.Path(__file__).parent.parent / "fixtures" / "parameters.json"
    
    template_text = template_path.read_text(encoding="utf-8")
    params_text = params_path.read_text(encoding="utf-8")
    
    # Get the actual findings from our analyzer
    findings = analyze_arm(IngestArgs(template_text=template_text, parameters_text=params_text))
    
    # Find the highest severity finding
    severity_order = {"high": 0, "med": 1, "low": 2}
    highest_severity_finding = min(findings.findings, key=lambda x: severity_order[x.severity])
    
    # Create the evaluation case
    case = Case(
        inputs={
            "template": template_text,
            "parameters": params_text,
            "prompt": f"""
Analyze this ARM template for security vulnerabilities and identify the highest priority issue:

Template:
{template_text}

Parameters:
{params_text}

What is the highest priority vulnerability in this ARM template? Provide the vulnerability ID, severity, and a brief explanation.
"""
        },
        expected_output={
            "highest_priority_vulnerability": highest_severity_finding.message,
            "vulnerability_id": highest_severity_finding.id,
            "severity": highest_severity_finding.severity,
            "explanation": f"This is a {highest_severity_finding.severity} severity issue that should be addressed first."
        }
    )
    
    dataset = Dataset(name="arm_vulnerability_analysis", cases=[case])
    print(f"Created dataset with {len(dataset.cases)} cases")
    return dataset

async def analyze_vulnerability_task(inputs: dict) -> VulnerabilityAnalysis:
    """Real LLM task function that analyzes ARM templates for vulnerabilities"""
    
    import os
    
    # Check if API key is set
    if not os.getenv('OPENAI_API_KEY'):
        raise ValueError("OPENAI_API_KEY environment variable is not set. Please set it to use the LLM agent.")
    
    try:
        # Create agent
        agent = Agent('openai:gpt-4o-mini', result_type=VulnerabilityAnalysis, system_prompt=SYSTEM_PROMPT)
        
        print(f"Running LLM analysis with prompt length: {len(inputs['prompt'])} characters")
        
        # Run the agent with the prompt
        result = await agent.run(inputs["prompt"])
        
        print(f"LLM response: {result.data}")
        return result.data
        
    except Exception as e:
        print(f"Error in LLM task: {e}")
        raise

def test_llm_vulnerability_identification():
    """Test LLM's ability to identify highest priority vulnerabilities"""
    
    # Create evaluation dataset
    dataset = create_arm_evaluation_dataset()
    
    # Create evaluators that check specific fields
    evaluators = [
        FieldContainsEvaluator(
            field_name="vulnerability_id",
            expected_value="IMG-001",
            evaluation_name="correct_vulnerability_id"
        ),
        FieldContainsEvaluator(
            field_name="severity",
            expected_value="med",
            evaluation_name="correct_severity"
        ),
        FieldContainsEvaluator(
            field_name="explanation",
            expected_value="security",
            evaluation_name="explanation_contains_security"
        )
    ]
    
    # Add evaluators to dataset
    for evaluator in evaluators:
        dataset.add_evaluator(evaluator)
    
    # Run evaluation using the real LLM task function
    import asyncio
    results = asyncio.run(dataset.evaluate(analyze_vulnerability_task))
    
    print("LLM Vulnerability Analysis Evaluation Results:")
    print("=" * 50)
    print(f"Number of cases: {len(results.cases)}")
    
    for case_result in results.cases:
        print(f"Case: {case_result.name}")
        print(f"Expected vulnerability ID: IMG-001")
        print(f"Expected severity: med")
        print(f"Actual vulnerability ID: {case_result.output.vulnerability_id}")
        print(f"Actual severity: {case_result.output.severity}")
        print(f"Assertions: {len(case_result.assertions)}")
        
        for assertion_name, assertion_result in case_result.assertions.items():
            print(f"  {assertion_name}: {assertion_result.value}")
            if not assertion_result.value:
                print(f"    Details: {assertion_result.reason}")
        print()
    
    # Summary
    total_cases = len(results.cases)
    passed_cases = sum(1 for case in results.cases if all(assertion_result.value for assertion_result in case.assertions.values()))
    
    print(f"Summary: {passed_cases}/{total_cases} cases passed")
    
    return results

def test_llm_priority_ranking():
    """Test LLM's ability to correctly rank vulnerabilities by priority"""
    
    # Create a more complex case with multiple vulnerabilities
    template_with_multiple_issues = """
    {
      "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
      "contentVersion": "1.0.0.0",
      "parameters": {
          "adminPassword": {
              "type": "securestring",
              "defaultValue": "Password123!"
          }
      },
      "resources": [
          {
              "type": "Microsoft.Compute/virtualMachines",
              "apiVersion": "2024-11-01",
              "name": "test-vm",
              "properties": {
                  "hardwareProfile": {
                      "vmSize": "Standard_D2s_v3"
                  },
                  "storageProfile": {
                      "imageReference": {
                          "publisher": "MicrosoftWindowsDesktop",
                          "offer": "Windows-10",
                          "sku": "win10-21h2-ent",
                          "version": "latest"
                      }
                  },
                  "osProfile": {
                      "adminUsername": "admin",
                      "adminPassword": "[parameters('adminPassword')]"
                  }
              }
          }
      ]
    }
    """
    
    # Create case for priority ranking
    case = Case(
        inputs={
            "template": template_with_multiple_issues,
            "parameters": '{"adminPassword": "Password123!"}',
            "prompt": f"""
Analyze this ARM template and identify the HIGHEST priority security vulnerability:

Template:
{template_with_multiple_issues}

Parameters:
{{"adminPassword": "Password123!"}}

Rank the vulnerabilities by priority and identify the most critical one that should be fixed first.
"""
        },
        expected_output={
            "highest_priority_vulnerability": "Hard-coded password in template",
            "vulnerability_id": "CRED-001",  # This would be a credential-related issue
            "severity": "high",
            "explanation": "Hard-coded passwords are a critical security risk that should be addressed immediately."
        }
    )
    
    dataset = Dataset(name="priority_ranking", cases=[case])
    
    # Create evaluators
    evaluators = [
        FieldContainsEvaluator(
            field_name="highest_priority_vulnerability",
            expected_value="password",
            evaluation_name="identifies_password_issue"
        ),
        FieldContainsEvaluator(
            field_name="severity",
            expected_value="high",
            evaluation_name="high_severity"
        )
    ]
    
    # Add evaluators to dataset
    for evaluator in evaluators:
        dataset.add_evaluator(evaluator)
    
    # Run evaluation with real LLM task
    import asyncio
    results = asyncio.run(dataset.evaluate(analyze_vulnerability_task))
    
    print("LLM Priority Ranking Evaluation Results:")
    print("=" * 50)
    
    for case_result in results.cases:
        print(f"Case: {case_result.name}")
        print(f"Expected: Password-related vulnerability with high severity")
        print(f"Actual: {case_result.output.highest_priority_vulnerability} (severity: {case_result.output.severity})")
        
        for assertion_name, assertion_result in case_result.assertions.items():
            print(f"  {assertion_name}: {assertion_result.value}")
            if not assertion_result.value:
                print(f"    Details: {assertion_result.reason}")
        print()
    
    return results

if __name__ == "__main__":
    print("Running LLM Evaluation Tests...")
    print("=" * 60)
    
    # Test 1: Basic vulnerability identification
    print("\n1. Testing vulnerability identification:")
    test_llm_vulnerability_identification()
    
    # Test 2: Priority ranking
    print("\n2. Testing priority ranking:")
    test_llm_priority_ranking()
    
    print("\nEvaluation complete!")