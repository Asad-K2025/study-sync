#!/bin/bash
set -e

python3 -m venv .venv
source .venv/bin/activate

python3 -m ensurepip --upgrade
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install -r requirements.txt

echo "Installation complete. Activate with: source .venv/bin/activate"
