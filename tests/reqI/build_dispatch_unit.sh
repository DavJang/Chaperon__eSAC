#!/bin/bash
# Build the dispatcher unit test from the EXACT production agent source (verbatim extraction, no edits).
set -e
A=${1:-$(cd "$(dirname "$0")/../.." && pwd)/agent/src/agent.cpp}
D=$(cd "$(dirname "$0")" && pwd)
python3 - "$A" "$D" <<'EOF'
import sys
a = open(sys.argv[1]).read(); d = sys.argv[2]
s = a.index("#define CHAP_MAX_SLOTS 64"); e = a.index("static inline void chap_run_prog", s)
open(d + "/dispatch_structs.inc", "w").write(a[s:e])
s = a.index("/* Request G: TX burst exclusion."); e = a.index("static __attribute__((noinline)) uint64_t chap_dispatch(uint32_t i,", s)
open(d + "/dispatch_excl.inc", "w").write(a[s:e])
print("extracted from", sys.argv[1])
EOF
sha256sum "$A" | cut -c1-16
g++ -std=c++17 -O2 -Wall -Wno-unused-function -o "$D/dispatch_unit_test" "$D/dispatch_unit_test.cpp"
