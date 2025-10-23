#!/usr/bin/env python3
"""
Example client to interact with the ARMAlyzer MCP server.
This demonstrates how to connect to and use the MCP server programmatically.
"""

import asyncio
import json
import pathlib
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def analyze_with_mcp_server(template_path: str, params_path: str):
    """Connect to MCP server and analyze ARM templates"""
    
    # Read template and parameters
    template_text = pathlib.Path(template_path).read_text(encoding="utf-8")
    params_text = pathlib.Path(params_path).read_text(encoding="utf-8")
    
    # Server parameters - adjust path as needed
    server_params = StdioServerParameters(
        command='python',
        args=['server.py'],
        cwd=str(pathlib.Path(__file__).parent)
    )
    
    print("Connecting to MCP server...")
    
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                print("Initializing session...")
                await session.initialize()
                
                print("Calling analyze_arm tool...")
                result = await session.call_tool('analyze_arm', {
                    'template_text': template_text,
                    'parameters_text': params_text
                })
                
                print("\n=== Analysis Results ===")
                print(result.content[0].text)
                
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure the MCP server is running or can be started.")

def main():
    """Main function for command line usage"""
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python client_example.py <template.json> <parameters.json>")
        print("Example: python client_example.py fixtures/template.json fixtures/parameters.json")
        sys.exit(1)
    
    template_path = sys.argv[1]
    params_path = sys.argv[2]
    
    # Run the async analysis
    asyncio.run(analyze_with_mcp_server(template_path, params_path))

if __name__ == "__main__":
    main()
