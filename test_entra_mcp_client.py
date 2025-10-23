#!/usr/bin/env python3
"""
Example client to test Entra ID analysis via MCP server.
"""

import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def test_entra_analysis():
    """Test Entra ID analysis via MCP server"""
    
    # Server parameters
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
                
                print("Calling analyze_entra tool...")
                result = await session.call_tool('analyze_entra', {
                    'backup_path': 'c:/EntraBackup',
                    'include_summary': True
                })
                
                print("\n=== Entra ID Analysis Results ===")
                print(result.content[0].text)
                
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    import pathlib
    asyncio.run(test_entra_analysis())
