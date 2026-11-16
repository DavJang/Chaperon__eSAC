#!/bin/bash
# Demo: eSAC resource admission gate. The launcher pre-screens a tenant's EAL resource request
# against its quota and REFUSES to exec an over-quota tenant -- so an attacker's repeated
# over-size launches are blocked before any kernel/NIC resource is touched. Pure control-plane.
# Portable: any Linux host. Run from the repo root:  bash demos/demo_admission.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
ADMIT="$ROOT/Resource_Bank/esac_admit.sh"
Q=/tmp/esac_quota.json; printf '{"max_socket_mem_mb":128,"max_lcore_count":2}\n' > "$Q"
echo "quota: $(cat "$Q")"
echo
echo "--- over-quota  (-m 9999 -l 0,1,2,3,4)  -> expect: DENY, tenant never execs ---"
bash "$ADMIT" "$Q" -- /bin/echo "TENANT-RAN" -m 9999 -l 0,1,2,3,4; rc=$?
echo "   exit=$rc  (2 = denied)"
echo
echo "--- within-quota (-m 64 -l 0,1)        -> expect: OK, tenant execs ---"
bash "$ADMIT" "$Q" -- /bin/echo "TENANT-RAN" -m 64 -l 0,1; rc=$?
echo "   exit=$rc  (0 = admitted; 'TENANT-RAN' above means the real tenant ran)"
