# Tests

Functional and regression checks run inside the launcher (`manager/run_3plane_F.sh`, modes in
[../docs/RUN.md](../docs/RUN.md)); each check is judged from the observed value and written to
`run/CHECKS.tsv` of the run directory. The verification blocks sourced by the launcher are in `manager/`
(`reqI_*_block.sh`, `reqJ_memrate_block.sh`, `reqI_perf1_block.sh`).

## Run chains

| Script | What it runs |
|---|---|
| `reqJ/reqJ_runs2.sh` | closing chain of the current build: memory-API rate (forged boundary, Agent graceful/kernel kill/2-CPU race), combined Table API + RESP + wildcard + unclassifiable run, RX/TX exclusion, NIC boundary, Sentinel concurrency test (an optional older Sentinel object for comparison: `CHAP_OLD_SENTINEL_OBJ`) |
| `reqJ/reqJ_runs.sh` | earlier closing chain (also covers `PROGFN_ATK`, `TAMPER`, `RXSLOT_PROBE`) |
| `reqI/reqI_runs.sh`, `reqI/run_resapi_matrix.sh` | Table API matrix (pre-check / kernel hard limit per API) |
| `reqI/reqI_two_tenant.sh` (+ `reqI_fabric3.sh`) | two tenants with separate policies on one PF (policy isolation) |

Run them as root from any directory; they read `manager/chap_env.sh`. Clear `/sys/fs/bpf/chap/*` between runs (the
chains do this).

## Test-only components

| Component | Purpose |
|---|---|
| `reqJ/chap_memapi_test.c` | driver thread inside the tenant that issues DPDK memory API calls on command (`MEMJ=…`); never part of a normal launch |
| `reqI/rawframes.py` | sends non-IPv4 / fragmented / malformed frames (`UNCLASS_TEST=1`) |
| `gen/esac_l47gen.c` | DPDK generator with exact L4 fields and payloads (functional checks) |
| `communication/combo/c_filter_hs_gate_excl_TESTFAILRX2.bpf.o` | fail build for `FAIL_INJECT=rx_window_fail` |
| `integrity/kernel/tamper_child.c` | tamper attempt for `TAMPER=1` |

## Unit tests

```sh
(cd tests/reqI && gcc -O2 -I../../communication lookup64_unit_test.c -o lookup64_unit_test && ./lookup64_unit_test)
bash tests/reqI/build_dispatch_unit.sh && tests/reqI/dispatch_unit_test   # dispatcher logic extracted verbatim from agent/src/agent.cpp
(cd tests/unit && gcc -O2 -I../../communication -o policy_writer_conc_test policy_writer_conc_test.c -lpthread)
(cd tests/unit && gcc -O2 -o seqlock_failclosed_test seqlock_failclosed_test.c -lpthread)
(cd tests/unit && gcc -O2 -o torn_stress torn_stress.c -lpthread)
(cd tests/unit && gcc -O2 -o hash_audit hash_audit.c)
(cd tests/unit && gcc -O2 -o hs_ufunc_failclosed_test hs_ufunc_failclosed_test.c -ldl)   # run from the repository root
(cd resource/kernel && sudo ./rs_concurrency_test resource_sentinel.bpf.o ./libstub_flow.so 1100 1110 atomic 200000 2 3)
```
