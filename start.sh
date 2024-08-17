#!/usr/bin/env bash

source ./.env

if [ ! -d "./env" ]; then
    python3 -m venv env
fi

source ./env/bin/activate &&
    # python ./main.py
    fastapi dev ./main.py --host "${HOST}" --port "${PORT}"
