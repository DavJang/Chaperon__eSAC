# Agent runtime

The Agent is the modified bpftime runtime that is preloaded into the tenant (`libbpftime-agent.so`) together with
the loader-side `libbpftime-syscall-server.so`. It runs the Communication Filter and the Resource Agent programs in
the tenant's address space.

## Contents

| Path | Description |
|---|---|
| `src/agent.cpp` | Agent entry (replaces bpftime `runtime/agent/agent.cpp`): sealed hook-to-filter dispatch (`replace_fast` thunks and a read-only slot table), RX burst compaction and TX burst exclusion in the dispatcher, immutable shared-memory view, execution gate before the executable's constructors, code-range registration, admitted-call boundary `chap_res_gate_enter` / `chap_res_gate_exit` for resource API calls, stack-argument forwarding |
| `src/array_map_kernel_user.cpp` | kernel-backed maps: read-only mmap, FD broker, FD removal |
| `src/ufunc.cpp`, `src/bpf_helper.cpp` | native ufunc registration and helpers used by the filters |
| `src/bpftime_shm.cpp`, `src/bpf_attach_ctx.cpp` | shared-memory and attach-context changes for the sealed dispatch |
| `src/include_override/` | `bpftime_prog.hpp` (accessor) and `chap_dispatch_reg.hpp` (dispatch registration), included first by the two files above |
| `patches/bpftime-base-edcc8ec.patch` | changes to the bpftime tree on which the runtime is built (kernel-backed maps, FD broker, RO mmap, FD removal, ufunc registration, Frida attach changes) |
| `patches/llvm-jit-8fc0cee.patch` | change inside the `vm/llvm-jit` submodule |
| `build_runtime.sh` | builds the runtime from the six sources above against a bpftime build |

## Build

1. Obtain bpftime at the base commit and its submodules:

   ```sh
   git clone https://github.com/eunomia-bpf/bpftime.git && cd bpftime
   git checkout edcc8ec && git submodule update --init --recursive
   git apply /path/to/chaperon/agent/patches/bpftime-base-edcc8ec.patch
   git -C vm/llvm-jit apply /path/to/chaperon/agent/patches/llvm-jit-8fc0cee.patch
   ```

2. Configure and build bpftime with compile commands exported. Options of the reference build:

   ```sh
   cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBPFTIME_BUILD_WITH_LIBBPF=ON -DBPFTIME_LLVM_JIT=ON \
         -DBPFTIME_UBPF_JIT=ON -DBPFTIME_ENABLE_FRIDA=ON -DBPFTIME_BUILD_KERNEL_BPF=ON
   cmake --build build -j
   ```

3. Build the Chaperon runtime (writes only to `OUT`):

   ```sh
   BPFTIME_SRC=/path/to/bpftime BPFTIME_BUILD=/path/to/bpftime/build OUT=/path/to/chaperon-runtime \
       bash agent/build_runtime.sh
   ```

   Set `CHAP_RUNTIME_DIR` in `manager/chap_env.sh` to `OUT`.

The patched `runtime/agent/agent.cpp` of the base tree is not used; `src/agent.cpp` replaces it.

## Versions

The frozen runtime used for the functional verification has sha256 `1495de2b` (agent) and `077464c5`
(syscall-server); see [../VERSION_MANIFEST.md](../VERSION_MANIFEST.md). The runtime embeds source file paths
(logging macros), so a build in a different directory has a different hash.
