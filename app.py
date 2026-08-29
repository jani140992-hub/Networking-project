"""
NetSphere Application Launcher (app.py).
Direct entry point for running the NetSphere platform.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from main import run_app

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 8080))
    run_app(host=host, port=port)
