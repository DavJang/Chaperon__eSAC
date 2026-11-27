/* Chaperon CI stub: stands in for rte_flow_create/destroy so the kernel uretprobe
 * accounting can be exercised WITHOUT a NIC/DPDK port.
 *   create(fail): returns NULL on failure (like rte_flow_create), non-NULL on success.
 *   destroy(fail): returns -1 on failure, 0 on success (like rte_flow_destroy). */
void *stub_flow_create(int fail) { return fail ? (void *)0 : (void *)0x1234; }
int   stub_flow_destroy(int fail) { return fail ? -1 : 0; }
