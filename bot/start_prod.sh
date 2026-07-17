#!/usr/bin/env bash
# Production startup for 74bot — installs deps then runs the bot.
set -e
cd "$(dirname "$0")"
pip install -q -r requirements.txt
exec python main.py
