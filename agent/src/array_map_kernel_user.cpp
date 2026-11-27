/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include "spdlog/spdlog.h"
#include <bpf_map/shared/array_map_kernel_user.hpp>
#include <cerrno>
#include <cstdlib>
#if __linux__
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#endif

#ifndef roundup
#define roundup(x, y)                                                          \
	({                                                                     \
		const decltype(y) __y = y;                                     \
		(((x) + (__y - 1)) / __y) * __y;                               \
	})
#endif // roundup

namespace bpftime
{

static size_t bpf_map_mmap_sz(unsigned int value_sz, unsigned int max_entries)
{
	const long page_sz = sysconf(_SC_PAGE_SIZE);
	size_t map_sz;

	map_sz = (size_t)roundup(value_sz, 8) * max_entries;
	map_sz = roundup(map_sz, page_sz);
	return map_sz;
}



// eSAC: receive a kernel-map fd from the privileged root loader's fd-broker over SCM_RIGHTS.
// Lets a NON-root agent (no CAP_BPF) obtain the fd without calling bpf_map_get_fd_by_id.
static int kpolicy_recv_fd_from_broker(const char *sockpath, int kernel_map_id)
{
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) return -1;
	struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, sockpath, sizeof sa.sun_path - 1);
	if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) { close(s); return -1; }
	uint32_t id = (uint32_t)kernel_map_id;
	if (write(s, &id, sizeof id) != (ssize_t)sizeof id) { close(s); return -1; }
	char dummy; char cbuf[CMSG_SPACE(sizeof(int))]; memset(cbuf, 0, sizeof cbuf);
	struct iovec iov; iov.iov_base = &dummy; iov.iov_len = 1;
	struct msghdr msg; memset(&msg, 0, sizeof msg);
	msg.msg_iov = &iov; msg.msg_iovlen = 1; msg.msg_control = cbuf; msg.msg_controllen = sizeof cbuf;
	int fd = -1;
	if (recvmsg(s, &msg, 0) > 0) {
		for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
			if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
				memcpy(&fd, CMSG_DATA(c), sizeof(int)); break;
			}
	}
	close(s);
	return fd;
}

bool array_map_kernel_user_impl::init_map_fd()
{
	if (!has_kernel_map) {
		return false;
	}
	if (mmap_ptr != nullptr) {
		return true; // eSAC FD-removal: already mapped, never re-acquire fd
	}
	if (map_fd >= 0) {
		return true;
	}
	const char *broker = getenv("BPFTIME_FD_BROKER_SOCK");
	if (broker) {
		map_fd = kpolicy_recv_fd_from_broker(broker, kernel_map_id);
		if (map_fd >= 0)
			SPDLOG_DEBUG("got kernel map fd {} from broker for id {}", map_fd, kernel_map_id);
	}
	if (map_fd < 0)
		map_fd = bpf_map_get_fd_by_id(kernel_map_id);
	if (map_fd < 0) {
		SPDLOG_ERROR("Failed to get fd for kernel map id {}",
			      kernel_map_id);
		return false;
	}
	bpf_map_info info = {};
	unsigned int info_len = sizeof(info);
	int res = bpf_obj_get_info_by_fd(map_fd, &info, &info_len);
	if (res < 0) {
		SPDLOG_ERROR("eSAC/chap: kernel map {} get_info FAILED errno={} -> init FAIL (fail-closed; no silent-ready)", kernel_map_id, errno);
		close(map_fd); map_fd = -1;   /* item-2: close the writable broker fd on failed init */
		return false;   /* review #1: was return true -> map looked ready with no mmap */
	}
	_value_size = info.value_size;
	_max_entries = info.max_entries;
	value_data.resize(_value_size);
	SPDLOG_DEBUG(
		"create kernel user array map value size {}, max entries {}",
		_value_size, _max_entries);
	// TODO: is the check here necessary?
	// if (!(info.map_flags & BPF_F_MMAPABLE)) {
	// 	SPDLOG_WARN("Map is not mmapable");
	// 	return;
	// }
	size_t mmap_sz = bpf_map_mmap_sz(_value_size, _max_entries);
	SPDLOG_DEBUG(
		"mmap shared array map, fd={}, mmap_sz={}, name={}, value_size={}, flags={}",
		map_fd, mmap_sz, info.name, info.value_size, info.map_flags);
	mmap_ptr = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (mmap_ptr == MAP_FAILED) {
		SPDLOG_ERROR("eSAC/chap: anon placeholder mmap FAILED kernel map {} errno={} sz={} -> init FAIL", kernel_map_id, errno, mmap_sz);
		mmap_ptr = nullptr;
		close(map_fd); map_fd = -1;   /* item-2: close the writable broker fd on failed init */
		return false;   /* review #1: was return true */
	}
	// What does this piece of code do?
	int prot;
	if ((info.map_flags & BPF_F_RDONLY_PROG) || getenv("BPFTIME_KERNEL_MAP_RO"))
		prot = PROT_READ; // eSAC: force RO so a non-RDONLY_PROG (seqlock-writable by root) policy map is still RO in the tenant
	else
		prot = PROT_READ | PROT_WRITE;
	void *mmaped = mmap(mmap_ptr, mmap_sz, prot, MAP_SHARED | MAP_FIXED,
			    map_fd, 0);
	if (mmaped == MAP_FAILED) {
		SPDLOG_ERROR("eSAC/chap: kernel-map {} RO re-mmap(MAP_SHARED|MAP_FIXED prot={}) FAILED errno={} map_flags={} -> init FAIL (NO per-lookup fallback; launch must refuse)", kernel_map_id, prot, errno, info.map_flags);
		munmap(mmap_ptr, mmap_sz);
		mmap_ptr = nullptr;
		close(map_fd); map_fd = -1;   /* item-2: close the writable broker fd on failed init */
		return false;   /* review #1: was return true -> silent-ready with null mmap */
	}
	mmap_ptr = mmaped;
	if (getenv("BPFTIME_KERNEL_MAP_DROP_FD")) {
		// eSAC FD-removal: drop the writable kernel-map fd so no in-process
		// writable handle to the policy map persists in the tenant address space.
		close(map_fd);
		map_fd = -1;
	}
	return true;
}

array_map_kernel_user_impl::array_map_kernel_user_impl(
	boost::interprocess::managed_shared_memory &memory, int km_id,
	uint32_t value_size, uint32_t max_entries)
	: value_data(1, memory.get_segment_manager()),
	  _value_size(value_size),
	  _max_entries(max_entries),
	  kernel_map_id(km_id),
	  has_kernel_map(km_id > 0),
	  mmap_ptr(nullptr)
{
	if (!has_kernel_map) {
		value_data.resize(static_cast<size_t>(_value_size) *
				  static_cast<size_t>(_max_entries));
	}
}

void *array_map_kernel_user_impl::elem_lookup(const void *key)
{
	if (!has_kernel_map) {
		auto key_val = *(uint32_t *)key;
		if (key_val >= _max_entries) {
			errno = ENOENT;
			return nullptr;
		}
		return &value_data[key_val * _value_size];
	}
	if (!init_map_fd())
		return nullptr;
	SPDLOG_DEBUG("Run lookup of shared array map, key={:x}",
		      (uintptr_t)key);
	if (mmap_ptr != nullptr) {
		auto key_val = *(uint32_t *)key;

		SPDLOG_DEBUG("mmap handled, key={}", key_val);
		if (key_val >= _max_entries) {
			errno = ENOENT;
			SPDLOG_DEBUG("Returned ENOENT");
			return nullptr;
		}
		auto result = &((uint8_t *)mmap_ptr)[key_val * _value_size];
		SPDLOG_DEBUG("Returned value addr: {:x}", (uintptr_t)result);
		return result;
	}
	// fallback to read kernel maps
	int res = bpf_map_lookup_elem(map_fd, key, value_data.data());
	if (res < 0) {
		return nullptr;
	}
	return (void *)value_data.data();
}

long array_map_kernel_user_impl::elem_update(const void *key, const void *value,
					     uint64_t flags)
{
	if (!has_kernel_map) {
		auto key_val = *(uint32_t *)key;
		if (key_val >= _max_entries) {
			errno = ENOENT;
			return -1;
		}
		std::copy((uint8_t *)value, (uint8_t *)value + _value_size,
			  &value_data[key_val * _value_size]);
		return 0;
	}
	if (!init_map_fd())
		return -1;
	if (mmap_ptr != nullptr) {
		auto key_val = *(uint32_t *)key;
		if (key_val >= _max_entries) {
			errno = ENOENT;
			return -1;
		}
		std::copy((uint8_t *)value, (uint8_t *)value + _value_size,
			  &((uint8_t *)mmap_ptr)[key_val * _value_size]);
		return 0;
	}
	// fallback to read kernel maps
	return bpf_map_update_elem(map_fd, key, value, flags);
}

long array_map_kernel_user_impl::elem_delete(const void *key)
{
	if (!has_kernel_map) {
		auto key_val = *(uint32_t *)key;
		if (key_val >= _max_entries) {
			errno = ENOENT;
			return -1;
		}
		memset(&value_data[key_val * _value_size], 0, _value_size);
		return 0;
	}
	if (!init_map_fd())
		return -1;
	if (mmap_ptr != nullptr) {
		auto key_val = *(uint32_t *)key;
		if (key_val >= _max_entries) {
			errno = ENOENT;
			return -1;
		}
		memset(&((uint8_t *)mmap_ptr)[key_val * _value_size], 0,
		       _value_size);
		return 0;
	}
	// fallback to read kernel maps
	return bpf_map_delete_elem(map_fd, key);
}

int array_map_kernel_user_impl::map_get_next_key(const void *key,
						 void *next_key)
{
	// Not found
	if (key == nullptr || *(uint32_t *)key >= _max_entries) {
		*(uint32_t *)next_key = 0;
		return 0;
	}
	uint32_t deref_key = *(uint32_t *)key;
	// Last element
	if (deref_key == _max_entries - 1) {
		errno = ENOENT;
		return -1;
	}
	auto key_val = *(uint32_t *)key;
	*(uint32_t *)next_key = key_val + 1;
	return 0;
}

array_map_kernel_user_impl::~array_map_kernel_user_impl()
{
	if (map_fd >= 0) {
		close(map_fd);
	}
}

} // namespace bpftime
