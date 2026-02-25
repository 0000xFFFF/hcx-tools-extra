#!/usr/bin/env bash
set -x
cd tools
make release
./setup-venv.sh