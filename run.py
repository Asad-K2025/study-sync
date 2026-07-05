#!/usr/bin/env python3
"""
Production entry point for StudySync.
For development with TLS, use run_secure.py instead.
"""

from dotenv import load_dotenv

load_dotenv()

from backend.app import create_app

app = create_app()

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8765))
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
