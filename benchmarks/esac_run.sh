#!/bin/bash
# esac_run.sh - canonical experiment launcher.
# Forces results into ~/eSAC-runs/<type>/<timestamp>_<desc>/ and records meta.json
# (git commit, ruleset sha256, config, timing). It WRAPS a command; it does NOT alter
# any existing harness's own logic -- adopt it for new runs so results stop landing in ~/.
#
# usage:  benchmarks/esac_run.sh <type> <desc> -- <command ...>
#   <type>: l4_intra | l4_inter | l7_intra | l7_inter | lcore | suricata | resource | tamper | other
# example: benchmarks/esac_run.sh l7_inter dnsaware_payload -- bash my_sweep.sh
#
# Harnesses that honor $ESAC_RUNS for their output root will write straight into the run dir;
# others still run correctly and at least their stdout/err is captured here.
set -u
TYPE="${1:?usage: esac_run.sh <type> <desc> -- <cmd...>}"
DESC="${2:?usage: esac_run.sh <type> <desc> -- <cmd...>}"
shift 2
[ "${1:-}" = "--" ] && shift

RUNS="${ESAC_RUNS_ROOT:-$HOME/eSAC-runs}"
TS=$(date +%Y%m%d_%H%M%S)
SAFE_DESC=$(echo "$DESC" | tr ' /' '__')
OUT="$RUNS/$TYPE/${TS}_${SAFE_DESC}"
mkdir -p "$OUT" || { echo "[esac_run] cannot create $OUT" >&2; exit 1; }

SELFDIR=$(cd "$(dirname "$0")" && pwd)
GITC=$(git -C "$SELFDIR/.." rev-parse --short HEAD 2>/dev/null || echo unknown)
RULESET="${ESAC_HS_PATTERNS:-}"
RULESHA=""
[ -n "$RULESET" ] && [ -f "$RULESET" ] && RULESHA=$(sha256sum "$RULESET" | cut -d' ' -f1)

cat > "$OUT/meta.json" <<JSON
{
  "type": "$TYPE",
  "desc": "$DESC",
  "started": "$(date -Iseconds)",
  "git_commit": "$GITC",
  "host": "$(hostname)",
  "ruleset": "$RULESET",
  "ruleset_sha256": "$RULESHA",
  "cmd": "$*",
  "env": {
    "ESAC_HS_PATTERNS": "${ESAC_HS_PATTERNS:-}",
    "KA": "${KA:-}", "GENCPS": "${GENCPS:-}", "GENCPU": "${GENCPU:-}"
  }
}
JSON

export ESAC_RUNS="$OUT"
echo "[esac_run] out=$OUT type=$TYPE commit=$GITC"
( "$@" ) 2>&1 | tee "$OUT/run.log"
rc=${PIPESTATUS[0]}
printf '{"ended":"%s","rc":%d}\n' "$(date -Iseconds)" "$rc" > "$OUT/meta_end.json"
echo "[esac_run] done rc=$rc out=$OUT"
exit "$rc"
