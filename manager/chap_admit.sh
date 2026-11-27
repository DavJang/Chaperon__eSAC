#!/bin/bash
# Chaperon Manager admission gate (Request I; replaces the use of FINAL eSAC/Resource_Bank/esac_admit.sh, which is
# kept unchanged). Pre-screens the EAL resource request of a tenant against its quota BEFORE exec. Over limit or
# not parsable -> refuse (exit 2, never exec). Within limit -> exec the tenant.
#   usage: chap_admit.sh <quota.json> -- <tenant cmd...>
# Parsed like the Agent's rte_eal_init check (chap_eal_args): -l/--lcores LIST (ranges a-b, comma lists, also
# attached -lLIST / --lcores=LIST), -c HEXMASK, no lcore option = every online CPU; -m MB, --socket-mem /
# --socket-limit LIST (sum per option, the larger counts). Arguments after "--" belong to the application.
set -u
Q=$1; shift; [ "${1:-}" = "--" ] && shift
CMD=("$@")
jget(){ grep -oE "\"$1\"[ ]*:[ ]*[0-9]+" "$Q" | grep -oE "[0-9]+$"; }
MAX_MB=$(jget max_socket_mem_mb); MAX_LC=$(jget max_lcore_count)
declare -A LC=(); HAVE_LC=0; REQ_MB=0; BAD=""
add_list(){ local v=$1 a b c; [ -z "$v" ] && { BAD="empty lcore list"; return; }
  IFS=',' read -ra P <<< "$v"
  for x in "${P[@]}"; do
    if [[ "$x" =~ ^([0-9]+)-([0-9]+)$ ]]; then a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}
    elif [[ "$x" =~ ^([0-9]+)$ ]]; then a=${BASH_REMATCH[1]}; b=$a
    else BAD="lcore list '$v'"; return; fi
    [ $b -lt $a ] || [ $b -gt 1023 ] && { BAD="lcore range '$x'"; return; }
    for ((c=a;c<=b;c++)); do LC[$c]=1; done
  done; HAVE_LC=1; }
add_mask(){ local m=$1 c; [[ "$m" =~ ^(0x)?[0-9a-fA-F]+$ ]] || { BAD="core mask '$m'"; return; }
  m=${m#0x}; local v=$((16#$m)); for ((c=0;c<63;c++)); do (( (v >> c) & 1 )) && LC[$c]=1; done; HAVE_LC=1; }
mem_list(){ local t=0 v; IFS=',' read -ra S <<< "$1"; for v in "${S[@]}"; do [[ "$v" =~ ^[0-9]+$ ]] || { BAD="memory '$1'"; return; }; t=$((t + v)); done
  [ $t -gt $REQ_MB ] && REQ_MB=$t; }
for ((i=0;i<${#CMD[@]};i++)); do
  a=${CMD[$i]}; n=${CMD[$((i+1))]:-}
  case "$a" in
    --) break ;;
    -l|--lcores) add_list "$n"; i=$((i+1)) ;;
    --lcores=*) add_list "${a#--lcores=}" ;;
    -l*) add_list "${a#-l}" ;;
    -c) add_mask "$n"; i=$((i+1)) ;;
    -c*) add_mask "${a#-c}" ;;
    -m) [[ "$n" =~ ^[0-9]+$ ]] || BAD="memory '$n'"; [ -z "$BAD" ] && [ "$n" -gt "$REQ_MB" ] && REQ_MB=$n; i=$((i+1)) ;;
    --socket-mem|--socket-limit) mem_list "$n"; i=$((i+1)) ;;
    --socket-mem=*) mem_list "${a#--socket-mem=}" ;;
  esac
done
[ $HAVE_LC = 0 ] && for ((c=0;c<$(nproc --all);c++)); do LC[$c]=1; done
REQ_LC=${#LC[@]}
DENY=0; R=""
[ -n "$BAD" ] && { DENY=1; R="$R unparsable $BAD"; }
[ -n "$MAX_MB" ] && [ "$REQ_MB" -gt "$MAX_MB" ] && { DENY=1; R="$R socket_mem ${REQ_MB}MB>${MAX_MB}MB"; }
[ -n "$MAX_LC" ] && [ "$REQ_LC" -gt "$MAX_LC" ] && { DENY=1; R="$R lcores ${REQ_LC}>${MAX_LC}"; }
if [ $DENY -eq 1 ]; then echo "[ADMIT] DENY (no exec):$R"; exit 2; fi
echo "[ADMIT] OK req_mb=$REQ_MB req_lc=$REQ_LC lcores=$(echo "${!LC[@]}" | tr ' ' '\n' | sort -n | paste -sd, -) -> exec tenant"
exec "${CMD[@]}"
