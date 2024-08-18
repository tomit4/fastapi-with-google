#!/usr/bin/env bash

source ./.env
VENV_PATH=$(poetry env info --path)

if [ ! -d "./.venv" ]; then
    python3 -m venv .venv
fi

source "${VENV_PATH}"/bin/activate &&
    fastapi dev ./main.py --host "${HOST}" --port "${PORT}"
