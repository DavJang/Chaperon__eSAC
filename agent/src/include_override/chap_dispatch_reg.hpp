#pragma once
/* Chaperon Request F: record of each Frida-backed bpf link (filled during trusted attach). */
#include <cstdint>
#include <mutex>
#include <vector>
namespace bpftime {
class bpftime_prog;
struct chap_link_rec { int link_id; int attach_type; uint64_t func; bool has_cookie; uint64_t cookie; const bpftime_prog *prog; };
extern std::vector<chap_link_rec> chap_link_registry;
extern std::mutex chap_link_registry_mu;
}
