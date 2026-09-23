"""Start the pinned upstream HTTP bridge without automatic backend discovery."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'third_party' / 'ghidra-mcp' / 'python'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8081)
    args = parser.parse_args()
    # Importing the official static tool definitions registers the protocol catalog.
    # We deliberately do not run cli.main(), which scans local Ghidra endpoints.
    import uvicorn
    from bridge_mcp_ghidra.cli import _build_http_app, _transport_security
    from bridge_mcp_ghidra.server import mcp
    from mcp_runtime import READ_TOOLS
    allowed = READ_TOOLS | {'list_instances', 'connect_instance', 'list_tool_groups', 'load_tool_group', 'check_tools', 'search_tools'}
    manager = mcp._tool_manager
    original_get, original_list = manager.get_tool, manager.list_tools
    manager.get_tool = lambda name: original_get(name) if name in allowed else None
    manager.list_tools = lambda: [tool for tool in original_list() if tool.name in allowed]
    mcp.settings.host = '127.0.0.1'
    mcp.settings.port = args.port
    mcp.settings.transport_security = _transport_security('127.0.0.1')
    app = _build_http_app('streamable-http', '127.0.0.1')
    print(f'Pinned Ghidra MCP bridge: http://127.0.0.1:{args.port}/mcp; backend auto-discovery disabled', flush=True)
    uvicorn.run(app, host='127.0.0.1', port=args.port, log_level='warning')


if __name__ == '__main__':
    main()
