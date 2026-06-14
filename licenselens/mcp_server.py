"""LICENSELENS MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from licenselens.core import DEFAULT_POLICY, build_sbom, scan_project


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
        """Dependency license + SBOM gate, developer-CLI first.

        Returns JSON findings for the requirements file at ``target``.
        """
        if not target:
            return json.dumps({"error": "target path is required"})
        try:
            result = scan_project(target, policy=DEFAULT_POLICY)
        except OSError as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(result.as_dict(), indent=2)

    @app.tool()
    def licenselens_sbom(target: str) -> str:
        """Emit a CycloneDX-1.5-style SBOM for the requirements file at ``target``."""
        if not target:
            return json.dumps({"error": "target path is required"})
        try:
            result = scan_project(target, policy=DEFAULT_POLICY)
        except OSError as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(build_sbom(result), indent=2)

    app.run()
    return 0
