#!/bin/bash
set -euo pipefail

if [[ "$1" == "Kalle" ]]; then
   echo -n deadbeefdeadbeef
   exit 0
else
    exit 1
fi
