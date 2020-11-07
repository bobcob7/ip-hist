#include <linux/bpf.h>
#include <stdint.h>
#include <linux/pkt_cls.h>
#include <iproute2/bpf_elf.h>
#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif
#ifndef __inline
# define __inline inline __attribute__((always_inline))
#endif
#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
   ((void)__sync_fetch_and_add(ptr, val))
#endif
#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif
static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);
struct bpf_elf_map packet_count __section("maps") = {
    .type           = BPF_MAP_TYPE_PERCPU_ARRAY,
    .size_key       = sizeof(uint32_t),
    .size_value     = sizeof(uint64_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 1,
};
__section("prog")
int xdp_prog(struct xdp_md *ctx)
{
    uint64_t *bytes;
	uint32_t key = 0;
    uint64_t value = 1;
    bytes = map_lookup_elem(&packet_count, &key);
    if (bytes)
            lock_xadd(bytes, value);
    return XDP_PASS;
}
char __license[] __section("license") = "GPL";