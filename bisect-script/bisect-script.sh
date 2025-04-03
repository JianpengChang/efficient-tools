#!/bin/bash

# exit code：
# 0 - good commit
# 1 - bad commit
# 125 - skip this commit (compile fail, e.g.)
SCRIPT_DIR=$(dirname "$(realpath "$0")")

python3 $SCRIPT_DIR/bisect.py

exit $?
