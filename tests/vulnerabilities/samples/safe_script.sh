#!/bin/sh
set -e
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python3 train.py --epochs 3
