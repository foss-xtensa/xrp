/*
 * Copyright (c) 2016 - 2017 Cadence Design Systems Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Alternatively you can use and distribute this file under the terms of
 * the GNU General Public License version 2 or later.
 */

#ifdef __KERNEL__

#include <asm/atomic.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>

#else

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "xrp_debug.h"

#define PAGE_SIZE 4096
#define GFP_KERNEL 0
#define ALIGN(v, a) (((v) + (a) - 1) & -(a))

static void *kmalloc(size_t sz, int flags)
{
	(void)flags;
	return malloc(sz);
}

static void *kzalloc(size_t sz, int flags)
{
	(void)flags;
	return calloc(1, sz);
}

static void kfree(void *p)
{
	free(p);
}

#endif

#include "xrp_private_alloc.h"

#ifndef __KERNEL__

static void mutex_init(struct mutex *mutex)
{
	xrp_mutex_init(&mutex->o);
}

static void mutex_lock(struct mutex *mutex)
{
	xrp_mutex_lock(&mutex->o);
}

static void mutex_unlock(struct mutex *mutex)
{
	xrp_mutex_unlock(&mutex->o);
}

static void atomic_set(atomic_t *p, uint32_t v)
{
	*((volatile atomic_t *)p) = v;
}

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	((type *)(__mptr - offsetof(type, member))); })

#endif

struct xrp_private_pool {
	struct xrp_allocation_pool pool;
	struct mutex free_list_lock;
	phys_addr_t start;
	u32 size;
	struct xrp_allocation *free_list;
};

static inline void xrp_pool_lock(struct xrp_private_pool *pool)
{
	mutex_lock(&pool->free_list_lock);
}

static inline void xrp_pool_unlock(struct xrp_private_pool *pool)
{
	mutex_unlock(&pool->free_list_lock);
}

static void xrp_private_free(struct xrp_allocation *xrp_allocation)
{
	struct xrp_private_pool *pool = container_of(xrp_allocation->pool,
						     struct xrp_private_pool,
						     pool);
	struct xrp_allocation **pcur;

	pr_debug("%s: %pap x %d\n", __func__,
		 &xrp_allocation->start, xrp_allocation->size);

	xrp_pool_lock(pool);

	for (pcur = &pool->free_list; ; pcur = &(*pcur)->next) {
		struct xrp_allocation *cur = *pcur;

		if (cur && cur->start + cur->size == xrp_allocation->start) {
			struct xrp_allocation *next = cur->next;

			pr_debug("merging block tail: %pap x 0x%x ->\n",
				 &cur->start, cur->size);
			cur->size += xrp_allocation->size;
			pr_debug("... -> %pap x 0x%x\n",
				 &cur->start, cur->size);
			kfree(xrp_allocation);

			if (next && cur->start + cur->size == next->start) {
				pr_debug("merging with next block: %pap x 0x%x ->\n",
					 &cur->start, cur->size);
				cur->size += next->size;
				cur->next = next->next;
				pr_debug("... -> %pap x 0x%x\n",
					 &cur->start, cur->size);
				kfree(next);
			}
			break;
		}

		if (!cur || xrp_allocation->start < cur->start) {
			if (cur && xrp_allocation->start + xrp_allocation->size ==
			    cur->start) {
				pr_debug("merging block head: %pap x 0x%x ->\n",
					 &cur->start, cur->size);
				cur->size += xrp_allocation->size;
				cur->start = xrp_allocation->start;
				pr_debug("... -> %pap x 0x%x\n",
					 &cur->start, cur->size);
				kfree(xrp_allocation);
			} else {
				pr_debug("inserting new free block\n");
				xrp_allocation->next = cur;
				*pcur = xrp_allocation;
			}
			break;
		}
	}

	xrp_pool_unlock(pool);
}

static long xrp_private_alloc(struct xrp_allocation_pool *pool,
			      u32 size, u32 align,
			      struct xrp_allocation **alloc)
{
	struct xrp_private_pool *ppool = container_of(pool,
						      struct xrp_private_pool,
						      pool);
	struct xrp_allocation **pcur;
	struct xrp_allocation *cur = NULL;
	struct xrp_allocation *new;
	phys_addr_t aligned_start = 0;
	bool found = false;

	if (!size || (align & (align - 1)))
		return -EINVAL;
	if (!align)
		align = 1;

	new = kzalloc(sizeof(struct xrp_allocation), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	align = ALIGN(align, PAGE_SIZE);
	size = ALIGN(size, PAGE_SIZE);

	xrp_pool_lock(ppool);

	/* on exit free list is fixed */
	for (pcur = &ppool->free_list; *pcur; pcur = &(*pcur)->next) {
		cur = *pcur;
		aligned_start = ALIGN(cur->start, align);

		if (aligned_start >= cur->start &&
		    aligned_start - cur->start + size <= cur->size) {
			if (aligned_start == cur->start) {
				if (aligned_start + size == cur->start + cur->size) {
					pr_debug("reusing complete block: %pap x %x\n",
						 &cur->start, cur->size);
					*pcur = cur->next;
				} else {
					pr_debug("cutting block head: %pap x %x ->\n",
						 &cur->start, cur->size);
					cur->size -= aligned_start + size - cur->start;
					cur->start = aligned_start + size;
					pr_debug("... -> %pap x %x\n",
						 &cur->start, cur->size);
					cur = NULL;
				}
			} else {
				if (aligned_start + size == cur->start + cur->size) {
					pr_debug("cutting block tail: %pap x %x ->\n",
						 &cur->start, cur->size);
					cur->size = aligned_start - cur->start;
					pr_debug("... -> %pap x %x\n",
						 &cur->start, cur->size);
					cur = NULL;
				} else {
					pr_debug("splitting block into two: %pap x %x ->\n",
						 &cur->start, cur->size);
					new->start = aligned_start + size;
					new->size = cur->start +
						cur->size - new->start;

					cur->size = aligned_start - cur->start;

					new->next = cur->next;
					cur->next = new;
					pr_debug("... -> %pap x %x + %pap x %x\n",
						 &cur->start, cur->size,
						 &new->start, new->size);

					cur = NULL;
					new = NULL;
				}
			}
			found = true;
			break;
		} else {
			cur = NULL;
		}
	}

	xrp_pool_unlock(ppool);

	if (!found) {
		kfree(cur);
		kfree(new);
		return -ENOMEM;
	}

	if (!cur) {
		cur = new;
		new = NULL;
	}
	if (!cur) {
		cur = kzalloc(sizeof(struct xrp_allocation), GFP_KERNEL);
		if (!cur)
			return -ENOMEM;
	}
	if (new)
		kfree(new);

	pr_debug("returning: %pap x %x\n", &aligned_start, size);
	cur->start = aligned_start;
	cur->size = size;
	cur->pool = pool;
	atomic_set(&cur->ref, 0);
	xrp_allocation_get(cur);
	*alloc = cur;

	return 0;
}

static void xrp_private_free_pool(struct xrp_allocation_pool *pool)
{
	struct xrp_private_pool *ppool = container_of(pool,
						      struct xrp_private_pool,
						      pool);
	kfree(ppool->free_list);
	kfree(ppool);
}

static phys_addr_t xrp_private_offset(const struct xrp_allocation *allocation)
{
	struct xrp_private_pool *ppool = container_of(allocation->pool,
						      struct xrp_private_pool,
						      pool);
	return allocation->start - ppool->start;
}

static const struct xrp_allocation_ops xrp_private_pool_ops = {
	.alloc = xrp_private_alloc,
	.free = xrp_private_free,
	.free_pool = xrp_private_free_pool,
	.offset = xrp_private_offset,
};

long xrp_init_private_pool(struct xrp_allocation_pool **ppool,
			   phys_addr_t start, u32 size)
{
	struct xrp_private_pool *pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	struct xrp_allocation *allocation = kmalloc(sizeof(*allocation),
						    GFP_KERNEL);

	if (!pool || !allocation) {
		kfree(pool);
		kfree(allocation);
		return -ENOMEM;
	}

	*allocation = (struct xrp_allocation){
		.pool = &pool->pool,
		.start = start,
		.size = size,
	};
	*pool = (struct xrp_private_pool){
		.pool = {
			.ops = &xrp_private_pool_ops,
		},
		.start = start,
		.size = size,
		.free_list = allocation,
	};
	mutex_init(&pool->free_list_lock);
	*ppool = &pool->pool;
	return 0;
}
