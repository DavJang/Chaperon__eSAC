#!/bin/sh
# Request Q: run the tenant command in its own network namespace (created by the launcher; it holds only lo and the
# tenant VF netdev, kept DOWN) and in a private mount namespace in which /proc/bus/pci is masked (CAP_SYS_RAWIO would
# otherwise allow read-only mmap of PCI BARs through it). Neither namespace grants the tenant anything: the tenant has
# no CAP_NET_ADMIN / CAP_SYS_ADMIN to change them.
#   tenant_ns_exec.sh <netns> <cmd> [args...]
NS=$1; shift
exec ip netns exec "$NS" /bin/sh -c 'mount -t tmpfs -o ro,nosuid,nodev,noexec,size=4k,mode=0555 chap_pci_mask /proc/bus/pci || { echo "tenant_ns_exec: /proc/bus/pci mask failed" >&2; exit 3; }; exec "$@"' tenant_ns_exec "$@"
