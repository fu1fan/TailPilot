#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
bash -n "$here/selftest.sh"
python3 "$here/test_batch.py"
# Existing fake native/planner/rehearsal tests, sequential and entirely local.
bash "$here/../../tests/selftest.sh"
