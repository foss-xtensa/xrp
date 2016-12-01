#ifndef XRP_ALLOC_H
#define XRP_ALLOC_H

#include <stdint.h>

typedef uint32_t u32;
typedef uint32_t phys_addr_t;
typedef uint32_t atomic_t;

struct xrp_allocation;

struct xrp_allocation_pool {
	phys_addr_t start;
	u32 size;
	struct xrp_allocation *free_list;
};

struct xrp_allocation {
	phys_addr_t start;
	u32 size;
	atomic_t ref;
	struct xrp_allocation *next;
	struct xrp_allocation_pool *pool;
};

long xrp_init_pool(struct xrp_allocation_pool *allocation_pool,
		   phys_addr_t start, u32 size);
void xrp_free(struct xrp_allocation *allocation);
long xrp_allocate(struct xrp_allocation_pool *allocation_pool,
		  u32 size, u32 align, struct xrp_allocation **alloc);

phys_addr_t xrp_allocation_offset(const struct xrp_allocation *allocation);

#endif
