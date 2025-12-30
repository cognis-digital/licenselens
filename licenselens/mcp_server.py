"""LICENSELENS MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from licenselens.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-licenselens[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-licenselens[mcp]'")
        return 1
    app = FastMCP("licenselens")

    @app.tool()
    def licenselens_scan(target: str) -> str:
        """Dependency license + SBOM gate, developer-CLI first. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
