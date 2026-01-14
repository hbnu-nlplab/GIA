#!/usr/bin/env python3
"""
간단한 MCP 서버 실행 스크립트

개별 서버를 쉽게 실행할 수 있습니다.

Usage:
    ./run_mcp_server.sh nso
    ./run_mcp_server.sh batfish
    ./run_mcp_server.sh pnetlab
    ./run_mcp_server.sh all      # FastMCP 통합 서버
"""

import sys
import argparse
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="NetConfigQA3 MCP 서버 실행")
    parser.add_argument(
        "server",
        choices=["nso", "batfish", "pnetlab", "telemetry", "all"],
        help="실행할 MCP 서버"
    )
    
    args = parser.parse_args()
    
    project_root = Path(__file__).parent
    
    server_map = {
        "nso": project_root / "mcp_servers" / "nso_server.py",
        "batfish": project_root / "mcp_servers" / "batfish_server.py",
        "pnetlab": project_root / "mcp_servers" / "pnetlab_server.py",
        "telemetry": project_root / "mcp_servers" / "telemetry_server.py",
        "all": project_root / "mcp_main.py",
    }
    
    server_file = server_map[args.server]
    
    print(f"🚀 Starting {args.server.upper()} MCP Server...")
    print(f"📁 File: {server_file}")
    print()
    
    try:
        subprocess.run([sys.executable, str(server_file)], check=True)
    except KeyboardInterrupt:
        print("\n⏹️  Server stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
