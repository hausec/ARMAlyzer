# ARMAlyzer - Azure Security Analysis Suite

A comprehensive security analysis tool for Azure ARM templates and Entra ID configurations using MCP (Model Context Protocol) and PydanticAI.

## Overview

ARMAlyzer provides security analysis for two critical Azure components:

### ARM Template Analysis
- **MCP Server**: Exposes analysis tools via Model Context Protocol
- **PydanticAI Agent**: Intelligent analysis and reporting
- **Security Checks**: Automated detection of common Azure ARM security issues
- **Evaluation Framework**: Testing and validation capabilities

### Entra ID Analysis
- **Backup Analysis**: Analyzes EntraExporter backup files for security misconfigurations
- **Policy Review**: Checks authorization policies, security defaults, and authentication methods
- **Role Analysis**: Identifies privileged users and role assignments
- **Sync Settings**: Reviews on-premises synchronization security settings

## Features

### ARM Template Security Checks

- **Image Version Pinning**: Detects use of "latest" image versions
- **Admin Credentials**: Identifies hardcoded admin usernames
- **Identity Management**: Analyzes managed identity configurations
- **Parameter Validation**: Checks for null or missing parameters
- **Network Security**: Reviews network interface configurations

### Entra ID Security Checks

- **Organization Settings**: Accidental deletion protection, notification emails
- **Authorization Policies**: Guest access, user permissions, app creation rights
- **Directory Roles**: Privileged user analysis, Global Administrator count
- **Sync Settings**: Password writeback, user writeback, device writeback
- **Security Defaults**: MFA enforcement, security policy compliance
- **Authentication Methods**: Weak vs strong authentication method analysis

### Architecture

```
├── server.py              # MCP server entry point
├── tools/
│   ├── arm_checks.py      # ARM template security analysis
│   ├── arm_ingest.py      # ARM MCP tool wrapper
│   ├── entra_analyzer.py  # Entra ID security analysis
│   └── entra_ingest.py    # Entra ID MCP tool wrapper
├── agent/
│   └── run_agent.py       # PydanticAI agent implementation
├── evals/
│   └── test_eval.py       # Evaluation tests
├── fixtures/
│   ├── template.json      # Sample ARM template
│   └── parameters.json    # Sample parameters
├── test_entra_analyzer.py # Entra ID analysis test script
└── test_entra_mcp_client.py # Entra ID MCP client test
```

## Installation

1. **Clone and setup**:
   ```bash
   git clone <your-repo>
   cd mcp_server
   pip install -r requirements.txt
   ```

2. **Set up OpenAI API key** (for PydanticAI agent):
   ```bash
   export OPENAI_API_KEY="your-api-key"
   ```

## Usage

### 1. MCP Server

Start the MCP server:

```bash
python server.py
```

The server exposes the `analyze_arm` tool that accepts:
- `template_text`: JSON content of ARM template
- `parameters_text`: JSON content of parameters file

### 2. Direct Analysis (Agent)

Run ARM template analysis with the agent:

```bash
python agent/run_agent.py arm fixtures/template.json fixtures/parameters.json
```

Run Entra ID analysis with the agent:

```bash
python agent/run_agent.py entra c:/EntraBackup
```

The agent provides AI-powered analysis with:
- Executive summaries
- Detailed findings tables
- Specific recommendations
- Structured reports

**Direct Analysis (without agent):**

Run Entra ID analysis directly:

```bash
python test_entra_analyzer.py c:/EntraBackup
```

### 3. Programmatic Usage

**ARM Template Analysis:**
```python
from tools.arm_ingest import analyze_arm, IngestArgs

# Load your template and parameters
template_text = open("template.json").read()
params_text = open("parameters.json").read()

# Analyze
findings = analyze_arm(IngestArgs(
    template_text=template_text,
    parameters_text=params_text
))

print(f"Found {findings.stats['total']} issues")
for finding in findings.findings:
    print(f"- {finding.severity}: {finding.message}")
```

**Entra ID Analysis:**
```python
from tools.entra_analyzer import analyze_entra_backup

# Analyze Entra ID backup
findings = analyze_entra_backup("c:/EntraBackup")

print(f"Found {findings.stats['total']} issues")
for finding in findings.findings:
    print(f"- {finding.severity}: {finding.message}")
```

### 4. MCP Client Integration

Connect to the MCP server from any MCP-compatible client:

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def analyze_template():
    server_params = StdioServerParameters(
        command='python', 
        args=['server.py']
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # ARM Template Analysis
            result = await session.call_tool('analyze_arm', {
                'template_text': template_json,
                'parameters_text': parameters_json
            })
            
            # Entra ID Analysis
            result = await session.call_tool('analyze_entra', {
                'backup_path': 'c:/EntraBackup',
                'include_summary': True
            })
            
            print(result.content[0].text)

asyncio.run(analyze_template())
```

## Testing

Run the evaluation tests:

**ARM Template Tests:**
```bash
python evals/test_eval.py
```

**Entra ID Tests:**
```bash
python evals/test_entra_eval.py
```

**All Tests:**
```bash
python evals/test_eval.py
python evals/test_entra_eval.py
```

The tests use sanitized fixture data to ensure consistent, predictable results.

## Security Findings

### ARM Template Findings

| ID | Severity | Description |
|----|----------|-------------|
| IMG-001 | Medium | Image version set to "latest" |
| OS-001 | Medium | Admin username hardcoded in template |
| MI-001 | Medium | Multiple managed identities assigned |
| PAR-001 | Low | Parameters with null values |

### Entra ID Findings

| ID | Severity | Category | Description |
|----|----------|----------|-------------|
| AUTH-008 | Critical | Policies | Default users can create tenants |
| AUTH-002 | High | Policies | Guest invitations allowed from everyone |
| AUTH-006 | High | Policies | Default users can create applications |
| ORG-004 | Medium | Organization | No security compliance notification emails |
| AUTH-003 | Medium | Policies | Email-based subscriptions signup allowed |
| SYNC-002 | Medium | Sync | Password writeback is disabled |
| AUTH-METHOD-FIDO2 | Medium | Auth | FIDO2 authentication method is disabled |
| ORG-005 | Low | Organization | Using legacy Azure AD tenant type |

## Configuration

### Environment Variables

- `OPENAI_API_KEY`: Required for PydanticAI agent functionality
- `MCP_LOG_LEVEL`: Set logging level (DEBUG, INFO, WARNING, ERROR)

### Customizing Checks

Modify `tools/arm_checks.py` to add new security checks:

```python
def check_custom_security(template: Dict[str, Any], parameters: Dict[str, Any]) -> List[Finding]:
    findings = []
    # Add your custom security checks here
    return findings
```

## Development

### Adding New Security Checks

1. Add check logic to `tools/arm_checks.py`
2. Update the `check_vm_template` function
3. Add test cases to `evals/test_eval.py`
4. Update documentation

### MCP Tool Development

The MCP server uses FastMCP for easy tool registration:

```python
@mcp.tool()
def your_custom_tool(param: str) -> str:
    """Your tool description."""
    return "result"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Create an issue in the repository
- Check the documentation
- Review the test cases for usage examples
