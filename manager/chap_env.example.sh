# Host-local paths for the Chaperon launcher. Copy to manager/chap_env.sh (not tracked by git) and edit.
# Sourced by manager/run_3plane_F.sh (and the test scripts) with `.`; plain shell assignments.

# Directory holding the Chaperon Agent runtime: libbpftime-agent.so + libbpftime-syscall-server.so
# (built by agent/build_runtime.sh). The launcher refuses to start without it.
CHAP_RUNTIME_DIR=/path/to/chaperon-runtime

# XDG_RUNTIME_DIR of the non-root DPDK tenant (created with mode 1777 by the launcher).
CHAP_DPDK_RUNDIR=/var/tmp/chap_dpdkrun

# LD_LIBRARY_PATH for the DPDK peer/generator processes (empty: system default).
CHAP_DPDK_LIBDIR=

# Optional overrides (defaults are the in-tree builds):
#CHAP_AMBLAUNCH=/path/to/manager/tools/amblaunch
#CHAP_GEN=/path/to/tests/gen/esac_l47gen

# Optional (tests/reqJ/reqJ_runs2.sh): an older Resource Sentinel object for the forged-gate comparison run.
#CHAP_OLD_SENTINEL_OBJ=/path/to/old/resource_sentinel.bpf.o

# Test-bed fabric (manager/fabric/setup_mlx5_fabric.sh): mlx5 PF PCI address and its netdev.
#export PF1=0000:3b:00.1 IF1=enp59s0f1np1
