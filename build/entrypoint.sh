#!/bin/sh
set -e
# session key is generated on first boot by the app itself (file-based, not env)
exec python3 /app/app.py
