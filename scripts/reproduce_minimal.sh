#!/usr/bin/env sh
set -eu
python -m unittest discover -s tests -v
cmake -S native/cpp -B build/cpp -DCMAKE_BUILD_TYPE=Release
cmake --build build/cpp --parallel
./build/cpp/mbl-probe --jsonl
