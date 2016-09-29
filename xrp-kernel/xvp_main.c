/*
 * XVP - Linux device driver for APK.
 * $Id$
 *
 * Copyright (c) 2015 Cadence Design Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Further, this software is distributed without any warranty that it
 * is free of the rightful claim of any third person regarding
 * infringement  or the like.  Any license provided herein, whether
 * implied or otherwise, applies only to this software file.  Patent
 * licenses, if any, provided herein do not apply to combinations of
 * this program with other software, or any other product whatsoever.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 */

#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <asm/mman.h>
#include <asm/uaccess.h>
#include "xvp_defs.h"

#define FIRMWARE_NAME "xvp.elf"
MODULE_FIRMWARE(FIRMWARE_NAME);

#define XVP_TIMEOUT_JIFFIES (HZ * 10)

#define XVP_REG_RESET		(0x00)
#define XVP_REG_RUNSTALL	(0x04)
#define XVP_REG_IVP_IRQ(num)	(0x14 + (num) * 4)
#define XVP_REG_HOST_IRQ(num)	(0x1014 + (num) * 4)

#define XVP_HOST_IRQ_NUM 5
#define XVP_IVP_IRQ_NUM 5

#define XVP_COMM_INIT_SYNC_LOC(core) ((core) * 4)
#define XVP_COMM_CMD (0x100)
#define XVP_COMM_DATA (0x200)
#define XVP_COMM_STATUS (0x300)
#define XVP_COMM_SIZE (0x400)

#define XVP_SYNC_MODE_IDLE      0
#define XVP_SYNC_MODE_POLL      1
#define XVP_SYNC_MODE_IRQ       2

#define XVP_SYNC(mode, host_irq_no, ivp_irq_no) \
	(((mode) ? XVP_SYNC_MODE_IRQ : XVP_SYNC_MODE_POLL) | \
	 (((host_irq_no) & 0xff) << 8) | \
	 (((ivp_irq_no) & 0xff) << 16))

#define XVP_CMD_IDLE (0)

enum xvp_comm {
	SYNC_POST_SYNC = 128,
};

struct xvp;
struct xvp_file;

struct xvp_alien_mapping {
	struct xvp_alien_mapping *next;
	unsigned long vaddr;
	unsigned long size;
	phys_addr_t paddr;
	void *allocation;
	enum {
		ALIEN_GUP,
		ALIEN_PFN_MAP,
		ALIEN_COPY,
	} type;
};

struct xvp_allocation {
	phys_addr_t start;
	u32 size;
	atomic_t ref;
	struct xvp_allocation *next;
	struct xvp_file *xvp_file;
};

struct xvp {
	struct device *dev;
	const struct firmware *firmware;
	struct miscdevice miscdev;

	void __iomem *regs;
	void __iomem *comm;
	phys_addr_t pmem;

	bool use_irq;
	struct completion completion;

	struct mutex free_list_lock;
	struct xvp_allocation *free_list;
	struct mutex comm_lock;
};

struct xvp_file {
	struct xvp *xvp;
	spinlock_t busy_list_lock;
	struct xvp_allocation *busy_list;
	struct mutex alien_list_lock;
	struct xvp_alien_mapping *alien_list;
};

static int firmware_reboot = 1;
module_param(firmware_reboot, int, 0644);
MODULE_PARM_DESC(firmware_reboot, "Reboot firmware on command timeout.");

static unsigned xvp_nodeid;

#define DRIVER_NAME "xvp"

static int xvp_boot_firmware(struct xvp *xvp);

static inline void xvp_reg_write32(struct xvp *xvp, unsigned addr, u32 v)
{
	__raw_writel(v, xvp->regs + addr);
}

static inline u32 xvp_reg_read32(struct xvp *xvp, unsigned addr)
{
	return __raw_readl(xvp->regs + addr);
}

static inline void xvp_comm_write32(struct xvp *xvp, unsigned addr, u32 v)
{
	__raw_writel(v, xvp->comm + addr);
}

static inline u32 xvp_comm_read32(struct xvp *xvp, unsigned addr)
{
	return __raw_readl(xvp->comm + addr);
}


static int xvp_synchronize(struct xvp *xvp)
{
	unsigned long deadline = jiffies + XVP_TIMEOUT_JIFFIES;

	xvp_comm_write32(xvp, XVP_COMM_INIT_SYNC_LOC(0), 0);
	mb();
	xvp_comm_write32(xvp, XVP_COMM_INIT_SYNC_LOC(1),
			 XVP_SYNC(xvp->use_irq,
				  XVP_HOST_IRQ_NUM,
				  XVP_IVP_IRQ_NUM));
	mb();

	if (xvp->use_irq)
		xvp_reg_write32(xvp, XVP_REG_IVP_IRQ(XVP_IVP_IRQ_NUM), 1);

	do {
		u32 v = xvp_comm_read32(xvp, XVP_COMM_INIT_SYNC_LOC(1));

		mb();
		if (v == 0) {
			xvp_comm_write32(xvp, XVP_COMM_INIT_SYNC_LOC(0),
					 SYNC_POST_SYNC);
			mb();
			if (xvp->use_irq) {
				int res = wait_for_completion_timeout(&xvp->completion,
								      XVP_TIMEOUT_JIFFIES);
				if (res == 0) {
					dev_err(xvp->dev,
						"IRQ mode is requested, but got no IRQ during synchronization\n");
					break;
				}
			}
			return 0;
		}
		schedule();
	} while (time_before(jiffies, deadline));

	xvp_comm_write32(xvp, XVP_COMM_INIT_SYNC_LOC(1), 0);

	return -ENODEV;
}

static irqreturn_t xvp_irq_handler(int irq, void *dev_id)
{
	struct xvp *xvp = dev_id;

	if (!xvp_reg_read32(xvp, XVP_REG_HOST_IRQ(XVP_HOST_IRQ_NUM)))
		return IRQ_NONE;

	xvp_reg_write32(xvp, XVP_REG_HOST_IRQ(XVP_HOST_IRQ_NUM), 0);
	complete(&xvp->completion);

	return IRQ_HANDLED;
}

static inline void xvp_memory_lock(struct xvp *xvp)
{
	mutex_lock(&xvp->free_list_lock);
}

static inline void xvp_memory_unlock(struct xvp *xvp)
{
	mutex_unlock(&xvp->free_list_lock);
}

static inline void xvp_file_lock(struct xvp_file *xvp_file)
{
	spin_lock(&xvp_file->busy_list_lock);
}

static inline void xvp_file_unlock(struct xvp_file *xvp_file)
{
	spin_unlock(&xvp_file->busy_list_lock);
}

static inline void xvp_alien_lock(struct xvp_file *xvp_file)
{
	mutex_lock(&xvp_file->alien_list_lock);
}

static inline void xvp_alien_unlock(struct xvp_file *xvp_file)
{
	mutex_unlock(&xvp_file->alien_list_lock);
}

static inline void xvp_allocation_get(struct xvp_allocation *xvp_allocation)
{
	atomic_inc(&xvp_allocation->ref);
}

static void xvp_free(struct xvp_allocation *xvp_allocation)
{
	struct xvp_file *xvp_file = xvp_allocation->xvp_file;
	struct xvp *xvp = xvp_file->xvp;
	struct xvp_allocation **pcur;

	pr_debug("%s: %pap x %d\n", __func__,
		 &xvp_allocation->start, xvp_allocation->size);

	xvp_memory_lock(xvp);

	for (pcur = &xvp->free_list; ; pcur = &(*pcur)->next) {
		struct xvp_allocation *cur = *pcur;

		if (cur && cur->start + cur->size == xvp_allocation->start) {
			struct xvp_allocation *next = cur->next;

			pr_debug("merging block tail: %pap x 0x%x ->\n",
				 &cur->start, cur->size);
			cur->size += xvp_allocation->size;
			pr_debug("... -> %pap x 0x%x\n",
				 &cur->start, cur->size);
			kfree(xvp_allocation);

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

		if (!cur || xvp_allocation->start < cur->start) {
			if (cur && xvp_allocation->start + xvp_allocation->size == cur->start) {
				pr_debug("merging block head: %pap x 0x%x ->\n",
					 &cur->start, cur->size);
				cur->size += xvp_allocation->size;
				cur->start = xvp_allocation->start;
				pr_debug("... -> %pap x 0x%x\n",
					 &cur->start, cur->size);
				kfree(xvp_allocation);
			} else {
				pr_debug("inserting new free block\n");
				xvp_allocation->next = cur;
				*pcur = xvp_allocation;
			}
			break;
		}
	}

	xvp_memory_unlock(xvp);
}

static inline void xvp_allocation_put(struct xvp_allocation *xvp_allocation)
{
	if (atomic_dec_and_test(&xvp_allocation->ref))
		xvp_free(xvp_allocation);
}

static long xvp_allocate(struct xvp_file *xvp_file,
			 u32 size, u32 align, u32 type,
			 struct xvp_allocation **alloc)
{
	struct xvp *xvp = xvp_file->xvp;
	struct xvp_allocation **pcur;
	struct xvp_allocation *cur = NULL;
	struct xvp_allocation *new;
	phys_addr_t aligned_start = 0;
	bool found = false;

	if (!size || (align & (align - 1)))
		return -EINVAL;
	if (!align)
		align = 1;

	new = kzalloc(sizeof(struct xvp_allocation), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	align = ALIGN(align, PAGE_SIZE);
	size = ALIGN(size, PAGE_SIZE);

	xvp_memory_lock(xvp);

	/* on exit free list is fixed */
	for (pcur = &xvp->free_list; *pcur; pcur = &(*pcur)->next) {
		cur = *pcur;
		aligned_start = ALIGN(cur->start, align);

		if (aligned_start >= cur->start &&
		    aligned_start - cur->start + size <= cur->size) {
			if (aligned_start == cur->start) {
				if (aligned_start + size == cur->start + cur->size) {
					pr_debug("reusing complete block: %pap x %x\n", &cur->start, cur->size);
					*pcur = cur->next;
				} else {
					pr_debug("cutting block head: %pap x %x ->\n", &cur->start, cur->size);
					cur->size -= aligned_start + size - cur->start;
					cur->start = aligned_start + size;
					pr_debug("... -> %pap x %x\n", &cur->start, cur->size);
					cur = NULL;
				}
			} else {
				if (aligned_start + size == cur->start + cur->size) {
					pr_debug("cutting block tail: %pap x %x ->\n", &cur->start, cur->size);
					cur->size = aligned_start - cur->start;
					pr_debug("... -> %pap x %x\n", &cur->start, cur->size);
					cur = NULL;
				} else {
					pr_debug("splitting block into two: %pap x %x ->\n", &cur->start, cur->size);
					new->start = aligned_start + size;
					new->size = cur->start + cur->size - new->start;

					cur->size = aligned_start - cur->start;

					new->next = cur->next;
					cur->next = new;
					pr_debug("... -> %pap x %x + %pap x %x\n", &cur->start, cur->size, &new->start, new->size);

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

	xvp_memory_unlock(xvp);

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
		cur = kzalloc(sizeof(struct xvp_allocation), GFP_KERNEL);
		if (!cur)
			return -ENOMEM;
	}
	if (new)
		kfree(new);

	pr_debug("returning: %pap x %x\n", &aligned_start, size);
	cur->start = aligned_start;
	cur->size = size;
	cur->xvp_file = xvp_file;
	atomic_set(&cur->ref, 0);
	xvp_allocation_get(cur);
	*alloc = cur;

	return 0;
}

static void xvp_allocation_queue(struct xvp_file *xvp_file,
				 struct xvp_allocation *xvp_allocation)
{
	xvp_file_lock(xvp_file);

	xvp_allocation->next = xvp_file->busy_list;
	xvp_file->busy_list = xvp_allocation;

	xvp_file_unlock(xvp_file);
}

static struct xvp_allocation *xvp_allocation_dequeue(struct xvp_file *xvp_file,
						     phys_addr_t paddr)
{
	struct xvp_allocation **pcur;
	struct xvp_allocation *cur;

	xvp_file_lock(xvp_file);

	for (pcur = &xvp_file->busy_list; (cur = *pcur); pcur = &((*pcur)->next)) {
		pr_debug("%s: %pap / %pap x %d\n", __func__, &paddr, &cur->start, cur->size);
		if (paddr >= cur->start && paddr < cur->start + cur->size) {
			*pcur = cur->next;
			break;
		}
	}

	xvp_file_unlock(xvp_file);
	return cur;
}

static void xvp_alien_mapping_add(struct xvp_file *xvp_file,
				  struct xvp_alien_mapping *alien_mapping)
{
	xvp_alien_lock(xvp_file);
	alien_mapping->next = xvp_file->alien_list;
	xvp_file->alien_list = alien_mapping;
	xvp_alien_unlock(xvp_file);
}

static struct xvp_alien_mapping *xvp_alien_mapping_find(struct xvp_file *xvp_file,
							unsigned long vaddr,
							unsigned long size)
{
	struct xvp_alien_mapping *cur;

	xvp_alien_lock(xvp_file);
	for (cur = xvp_file->alien_list; cur; cur = cur->next) {
		if (vaddr >= cur->vaddr &&
		    vaddr + size <= cur->vaddr + cur->size)
			break;
		if (vaddr < cur->vaddr + cur->size &&
		    vaddr + size > cur->vaddr)
			pr_debug("%s: overlapping alien mappings 0x%08lx x 0x%08lx and 0x%08lx x 0x%08lx\n",
				 __func__, vaddr, size, cur->vaddr, cur->size);
	}
	xvp_alien_unlock(xvp_file);
	return cur;
}

static long xvp_ioctl_alloc(struct file *filp,
			    struct xvp_ioctlx_alloc __user *p)
{
	struct xvp_file *xvp_file = filp->private_data;
	struct xvp_allocation *xvp_allocation;
	unsigned long vaddr;
	struct xvp_ioctlx_alloc xvp_ioctlx_alloc;
	long err;

	pr_debug("%s: %p\n", __func__, p);
	if (copy_from_user(&xvp_ioctlx_alloc, p, sizeof(*p)))
		return -EFAULT;

	pr_debug("%s: size = %d, align = %x, type = %d\n", __func__,
		 xvp_ioctlx_alloc.size, xvp_ioctlx_alloc.align, xvp_ioctlx_alloc.type);

	err = xvp_allocate(xvp_file, xvp_ioctlx_alloc.size,
			   xvp_ioctlx_alloc.align,
			   xvp_ioctlx_alloc.type,
			   &xvp_allocation);
	if (err)
		return err;

	xvp_allocation_queue(xvp_file, xvp_allocation);

	vaddr = vm_mmap(filp, 0, xvp_allocation->size,
			PROT_READ | PROT_WRITE, MAP_SHARED,
			xvp_allocation->start - xvp_file->xvp->pmem);

	xvp_ioctlx_alloc.phys_addr = xvp_allocation->start;
	xvp_ioctlx_alloc.virt_addr = vaddr;

	if (copy_to_user(p, &xvp_ioctlx_alloc, sizeof(*p))) {
		vm_munmap(vaddr, xvp_ioctlx_alloc.size);
		return -EFAULT;
	}
	return 0;
}

#if defined(__XTENSA__)
static void xvp_clean_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
	__flush_dcache_range((unsigned long)vaddr, sz);
}
static void xvp_flush_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
	__flush_dcache_range((unsigned long)vaddr, sz);
	__invalidate_dcache_range((unsigned long)vaddr, sz);
}
static void xvp_invalidate_cache(void *vaddr, phys_addr_t paddr,
				 unsigned long sz)
{
	__invalidate_dcache_range((unsigned long)vaddr, sz);
}
#elif defined(__arm__)
static void xvp_clean_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
	__cpuc_flush_dcache_area(vaddr, sz);
	outer_clean_range(paddr, paddr + sz);
}
static void xvp_flush_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
	__cpuc_flush_dcache_area(vaddr, sz);
	outer_flush_range(paddr, paddr + sz);
}
static void xvp_invalidate_cache(void *vaddr, phys_addr_t paddr,
				 unsigned long sz)
{
	__cpuc_flush_dcache_area(vaddr, sz);
	outer_inv_range(paddr, paddr + sz);
}
#else
#error "cache operations are not implemented for this architecture"
#endif

static struct xvp_alien_mapping *
xvp_alien_mapping_create(struct xvp_alien_mapping mapping)
{
	struct xvp_alien_mapping *alien_mapping =
		kmalloc(sizeof(*alien_mapping), GFP_KERNEL);

	if (!alien_mapping)
		return NULL;

	*alien_mapping = mapping;
	return alien_mapping;
}

static void xvp_alien_mapping_destroy(struct xvp_alien_mapping *alien_mapping)
{
	int i;
	struct page *page;
	int nr_pages;

	switch (alien_mapping->type) {
	case ALIEN_GUP:
		page = pfn_to_page(__phys_to_pfn(alien_mapping->paddr));
		nr_pages =
			((alien_mapping->vaddr + alien_mapping->size +
			  PAGE_SIZE - 1) >> PAGE_SHIFT) -
			(alien_mapping->vaddr >> PAGE_SHIFT);
		for (i = 0; i < nr_pages; ++i)
			put_page(page + i);
		break;
	case ALIEN_COPY:
		kfree(alien_mapping->allocation);
		break;
	default:
		break;
	}
	kfree(alien_mapping);
}

static long xvp_pfn_map_virt_to_phys(struct xvp_file *xvp_file,
				     struct vm_area_struct *vma,
				     unsigned long vaddr, unsigned long size,
				     unsigned long *paddr,
				     struct xvp_alien_mapping **mapping)
{
	int i;
	int ret;
	int nr_pages =
		((vaddr + size + PAGE_SIZE - 1) >> PAGE_SHIFT) -
		(vaddr >> PAGE_SHIFT);
	unsigned long pfn;
	struct xvp_alien_mapping *alien_mapping;

	ret = follow_pfn(vma, vaddr, &pfn);
	if (ret)
		return ret;

	*paddr = __pfn_to_phys(pfn) + (vaddr & ~PAGE_MASK);
	for (i = 1; i < nr_pages; ++i) {
		unsigned long next_pfn;

		ret = follow_pfn(vma, vaddr + (i << PAGE_SHIFT), &next_pfn);
		if (ret)
			return ret;
		if (next_pfn != pfn + 1) {
			pr_debug("%s: non-contiguous physical memory\n",
				 __func__);
			return -EINVAL;
		}
		pfn = next_pfn;
	}
	alien_mapping = xvp_alien_mapping_create((struct xvp_alien_mapping){
						 .vaddr = vaddr,
						 .size = size,
						 .paddr = *paddr,
						 .type = ALIEN_PFN_MAP,
						 });
	if (!alien_mapping)
		return -ENOMEM;

	*mapping = alien_mapping;
	pr_debug("%s: success, paddr: 0x%08lx\n", __func__, *paddr);
	return 0;
}

static long xvp_gup_virt_to_phys(struct xvp_file *xvp_file,
				 unsigned long vaddr, unsigned long size,
				 unsigned long *paddr,
				 struct xvp_alien_mapping **mapping)
{
	int ret;
	int i;
	int nr_pages =
		((vaddr + size + PAGE_SIZE - 1) >> PAGE_SHIFT) -
		(vaddr >> PAGE_SHIFT);
	struct page **page = kmalloc(nr_pages * sizeof(void *), GFP_KERNEL);
	struct xvp_alien_mapping *alien_mapping;

	if (!page)
		return -ENOMEM;

	ret = get_user_pages_fast(vaddr, nr_pages, 1, page);
	if (ret < 0)
		goto out;

	if (ret < nr_pages) {
		pr_debug("%s: asked for %d pages, but got only %d\n",
			 __func__, nr_pages, ret);
		nr_pages = ret;
		ret = -EINVAL;
		goto out_put;
	}

	for (i = 1; i < nr_pages; ++i) {
		if (page[i] != page[i - 1] + 1) {
			pr_debug("%s: non-contiguous physical memory\n",
				 __func__);
			ret = -EINVAL;
			goto out_put;
		}
	}

	*paddr = __pfn_to_phys(page_to_pfn(page[0])) + (vaddr & ~PAGE_MASK);
	alien_mapping = xvp_alien_mapping_create((struct xvp_alien_mapping){
						 .vaddr = vaddr,
						 .size = size,
						 .paddr = *paddr,
						 .type = ALIEN_GUP,
						 });
	if (!alien_mapping) {
		ret = -ENOMEM;
		goto out_put;
	}

	*mapping = alien_mapping;
	ret = 0;
	pr_debug("%s: success, paddr: 0x%08lx\n", __func__, *paddr);

out_put:
	if (ret < 0)
		for (i = 0; i < nr_pages; ++i)
			put_page(page[i]);
out:
	kfree(page);
	return ret;
}

static long xvp_copy_virt_to_phys(struct xvp_file *xvp_file,
				  unsigned long *vaddr, unsigned long size,
				  unsigned long *paddr,
				  struct xvp_alien_mapping **mapping)
{
	unsigned long phys;
	unsigned long offset = *vaddr & (PAGE_SIZE - 1);
	void *allocation = kmalloc(size + (offset ? PAGE_SIZE : 0),
				   GFP_KERNEL);
	void *p;
	struct xvp_alien_mapping *alien_mapping;

	if (!allocation)
		return -ENOMEM;

	p = (void *)((((unsigned long)allocation) & PAGE_MASK) | offset);
	if (p < allocation)
		p += PAGE_SIZE;

	if (copy_from_user(p, (void *)*vaddr, size)) {
		kfree(p);
		return -EFAULT;
	}

	phys = __pa(p);
	*paddr = phys;
	alien_mapping = xvp_alien_mapping_create((struct xvp_alien_mapping){
						 .vaddr = *vaddr,
						 .size = size,
						 .paddr = *paddr,
						 .allocation = allocation,
						 .type = ALIEN_COPY,
						 });
	if (!alien_mapping) {
		kfree(allocation);
		return -ENOMEM;
	}

	*mapping = alien_mapping;
	*vaddr = (unsigned long)p;
	pr_debug("%s: copying to pa: 0x%08lx\n", __func__, phys);

	return 0;
}

/*
 * Update alien mapping, and possibly the mapping record.
 *
 * new_mapping may be freed when this function returns.
 *
 * We make kernel shadow copy for non-linear 3rd-party regions. Data need to
 * be copied into or out of that shadow on every share and invalidate IOCTL.
 *
 * Mapping could change type (e.g. physically linear user memory could become
 * non-linear) or physical address. When that happens update mapping record.
 */
static long xvp_alien_mapping_update(struct xvp_file *xvp_file,
				     struct xvp_alien_mapping *old_mapping,
				     struct xvp_alien_mapping *new_mapping,
				     bool to_device)
{
	if (old_mapping->type == ALIEN_COPY) {
		if (to_device) {
			if (copy_from_user(__va(old_mapping->paddr),
					   (void *)old_mapping->vaddr,
					   old_mapping->size))
				return -EFAULT;
		} else {
			if (copy_to_user((void *)old_mapping->vaddr,
					 __va(old_mapping->paddr),
					 old_mapping->size))
				return -EFAULT;
		}
		return 0;
	}

	if (old_mapping->type != new_mapping->type) {
		pr_debug("%s: mapping type changed: %d -> %d\n",
			 __func__, old_mapping->type, new_mapping->type);
		xvp_alien_mapping_add(xvp_file, new_mapping);
		return 0;
	}

	switch (new_mapping->type) {
	case ALIEN_GUP:
		if (old_mapping->paddr != new_mapping->paddr) {
			pr_debug("%s: ALIEN_GUP: physical address changed\n",
				 __func__);
			/*
			 * We need both pages of the old and the new mapping
			 * to stay locked until they're no longer used.
			 * Record new mapping that overrides the old one.
			 */
			xvp_alien_mapping_add(xvp_file, new_mapping);
		} else {
			xvp_alien_mapping_destroy(new_mapping);
		}
		break;
	case ALIEN_PFN_MAP:
		if (old_mapping->paddr != new_mapping->paddr) {
			pr_debug("%s: ALIEN_PFN_MAP: physical address changed\n",
				 __func__);
			/* Nothing needs to be done for the PFN mapping when
			 * it's no longer needed. Just update physical address
			 * of the old mapping.
			 */
			old_mapping->paddr = new_mapping->paddr;
		}
		xvp_alien_mapping_destroy(new_mapping);
		break;
	default:
		break;
	}
	return 0;
}

static unsigned xvp_get_region_vma_count(unsigned long virt,
					 unsigned long size,
					 struct vm_area_struct *vma)
{
	unsigned i;
	struct mm_struct *mm = current->mm;

	if (vma->vm_start > virt)
		return 0;
	if (vma->vm_start <= virt &&
	    virt + size <= vma->vm_end)
		return 1;
	for (i = 2; ; ++i) {
		struct vm_area_struct *next_vma = find_vma(mm, vma->vm_end);

		if (!next_vma)
			return 0;
		if (next_vma->vm_start != vma->vm_end)
			return 0;
		vma = next_vma;
		if (virt + size <= vma->vm_end)
			return i;
	}
	return 0;
}

/* Share blocks of memory, from host to IVP or back.
 *
 * When sharing to IVP return physical addresses in paddr.
 * Areas allocated from the driver can always be shared in both directions.
 * Contiguous 3rd party allocations need to be shared to IVP before they can
 * be shared back.
 * Non-contiguous 3rd party allocations can only be shared from host to IVP
 * currently.
 *
 * When sharing from IVP paddr is NULL.
 */
static long __xvp_share_block(struct file *filp,
			      unsigned long virt, unsigned long *paddr,
			      unsigned long size)
{
	struct xvp_file *xvp_file = filp->private_data;
	struct mm_struct *mm = current->mm;
	unsigned long phys = ~0ul;
	struct vm_area_struct *vma = find_vma(mm, virt);
	long rc;

	if (!vma) {
		pr_debug("%s: no vma for vaddr/size = 0x%08lx/0x%08lx\n",
			 __func__, virt, size);
		return -EINVAL;
	}
	/*
	 * Region requested for sharing should be within single VMA.
	 * That's true for the majority of cases, but sometimes (e.g.
	 * sharing buffer in the beginning of .bss which shares a
	 * file-mapped page with .data, followed by anonymous page)
	 * region will cross multiple VMAs. Support it in the simplest
	 * way possible: start with get_user_pages and use shadow copy
	 * if that fails.
	 */
	switch (xvp_get_region_vma_count(virt, size, vma)) {
	case 0:
		pr_debug("%s: bad vma for vaddr/size = 0x%08lx/0x%08lx\n",
			 __func__, virt, size);
		pr_debug("%s: vma->vm_start = 0x%08lx, vma->vm_end = 0x%08lx\n",
			 __func__, vma->vm_start, vma->vm_end);
		return -EINVAL;
	case 1:
		break;
	default:
		pr_debug("%s: multiple vmas cover vaddr/size = 0x%08lx/0x%08lx\n",
			 __func__, virt, size);
		vma = NULL;
		break;
	}
	/*
	 * And it need to be allocated from the same file descriptor.
	 */
	if (vma && vma->vm_file == filp) {
		struct xvp_allocation *xvp_allocation =
			vma->vm_private_data;

		phys = xvp_allocation->start +
			virt - vma->vm_start;
	} else {
		struct xvp_alien_mapping *old_mapping;
		struct xvp_alien_mapping *new_mapping = NULL;

		/* Otherwise this is alien allocation. */
		pr_debug("%s: non-XVP allocation at 0x%08lx\n",
			 __func__, virt);

		/*
		 * We may have shared it already, try to find a
		 * record.
		 */
		old_mapping = xvp_alien_mapping_find(xvp_file, virt, size);

		/*
		 * If it hasn't been shared and we're sharing towards
		 * the CPU, that's an error: IVP had to have a physical
		 * address to write to.
		 */
		if (!old_mapping && !paddr) {
			pr_debug("%s: not previously locked\n", __func__);
			return -EINVAL;
		}
		/*
		 * If it hasn't been shared (old_mapping == NULL),
		 * share it for the first time. We know that we share
		 * towards IVP.
		 *
		 * If it has already been shared (old_mapping != NULL),
		 * and we care about virtual-to-physical mapping (it's
		 * not a shadow copy) share it again and see if the
		 * virtual-to-physical mapping has changed.
		 */
		if (!old_mapping || old_mapping->type != ALIEN_COPY) {
			if (vma && vma->vm_flags & (VM_IO | VM_PFNMAP)) {
				rc = xvp_pfn_map_virt_to_phys(xvp_file, vma,
							      virt, size,
							      &phys,
							      &new_mapping);
			} else {
				up_read(&mm->mmap_sem);
				rc = xvp_gup_virt_to_phys(xvp_file, virt,
							  size, &phys,
							  &new_mapping);
				down_read(&mm->mmap_sem);
			}

			/*
			 * If we couldn't share and we share towards
			 * IVP, try to make a shadow copy.
			 */
			if (rc < 0 && paddr)
				rc = xvp_copy_virt_to_phys(xvp_file, &virt,
							   size, &phys,
							   &new_mapping);

			/* We couldn't share it. Fail the request. */
			if (rc < 0) {
				pr_debug("%s: couldn't map virt to phys\n",
					 __func__);
				return -EINVAL;
			}
			/* At this point new_mapping != NULL */
		} else {
			/*
			 * Once we've switched to a shadow copy,
			 * maintain it.
			 */
			new_mapping = old_mapping;
		}

		/* If there's been a share record... */
		if (old_mapping) {
			phys = new_mapping->paddr +
				virt - new_mapping->vaddr;

			/* ...update it with the new mapping... */
			rc = xvp_alien_mapping_update(xvp_file,
						      old_mapping,
						      new_mapping,
						      paddr != NULL);
			if (rc < 0)
				return rc;

			pr_debug("%s: found mapping, paddr: 0x%08lx\n",
				 __func__, phys);
		} else {
			/* ...otherwise record the mapping. */
			xvp_alien_mapping_add(xvp_file, new_mapping);
		}
	}
	if (paddr) {
		xvp_clean_cache((void *)virt, phys, size);
		*paddr = phys;
	} else {
		xvp_invalidate_cache((void *)virt, phys, size);
	}
	return 0;
}

static long xvp_share_block(struct file *filp,
			    unsigned long virt, unsigned long *paddr,
			    unsigned long size)
{
	struct mm_struct *mm = current->mm;
	long rc;

	down_read(&mm->mmap_sem);
	rc = __xvp_share_block(filp, virt, paddr, size);
	up_read(&mm->mmap_sem);
	return rc;
}

static long xvp_share_blocks(struct file *filp, unsigned n,
			     unsigned long *vaddr, unsigned long *paddr,
			     unsigned long *size)
{
	struct mm_struct *mm = current->mm;
	unsigned i;
	long rc = 0;

	down_read(&mm->mmap_sem);
	for (i = 0; i < n; ++i) {
		rc = __xvp_share_block(filp, vaddr[i],
				       paddr ? paddr + i : NULL,
				       size[i]);
		if (rc < 0)
			break;
	}
	up_read(&mm->mmap_sem);
	return rc;
}

static long xvp_share_with_core(struct file *filp, unsigned n,
				__u32 __user *user_addr, unsigned long *addr,
				unsigned long *size)
{
	long ret = xvp_share_blocks(filp, n, addr, addr, size);

	if (ret == 0 &&
	    copy_to_user(user_addr, addr, n * sizeof(u32)))
		ret = -EFAULT;
	return ret;
}

static long xvp_share_from_core(struct file *filp, unsigned n,
				__u32 __user *user_addr, unsigned long *addr,
				unsigned long *size)
{
	return xvp_share_blocks(filp, n, addr, NULL, size);
}

static long xvp_process_buffers(struct file *filp,
				unsigned num_buffers,
				__u32 __user *user_addr,
				__u32 __user *user_size,
				long (*f)(struct file *filp,
					  unsigned n,
					  __u32 __user *user_addr,
					  unsigned long *addr,
					  unsigned long *size))
{
	unsigned long *addr;
	unsigned long *size;
	unsigned n = num_buffers;
	unsigned off;
	long ret;

	if (n > PAGE_SIZE / sizeof(unsigned long))
		n = PAGE_SIZE / sizeof(unsigned long);

	addr = kmalloc(n * sizeof(unsigned long), GFP_KERNEL);
	size = kmalloc(n * sizeof(unsigned long), GFP_KERNEL);
	if (!addr || !size) {
		ret = -ENOMEM;
		goto err;
	}
	for (off = 0; off < num_buffers; off += n) {
		unsigned count = min(n, num_buffers - off);

		if (copy_from_user(addr, user_addr + off, count * sizeof(u32)) ||
		    copy_from_user(size, user_size + off, count * sizeof(u32))) {
			ret = -EFAULT;
			goto err;
		}
		ret = f(filp, count, user_addr + off, addr, size);
		if (ret)
			goto err;
	}
err:
	kfree(addr);
	kfree(size);
	return ret;
}

static long xvp_ioctl_virt_to_phys(struct file *filp,
				   struct xvp_ioctlq_get_paddr __user *p)
{
	struct xvp_ioctlq_get_paddr xvp_ioctlq_get_paddr;

	pr_debug("%s: %p\n", __func__, p);

	if (copy_from_user(&xvp_ioctlq_get_paddr, p, sizeof(*p)))
		return -EFAULT;

	return xvp_process_buffers(filp,
				   xvp_ioctlq_get_paddr.num_addr,
				   (__u32 __user *)xvp_ioctlq_get_paddr.addrs,
				   (__u32 __user *)xvp_ioctlq_get_paddr.sizes,
				   xvp_share_with_core);
}

static long xvp_ioctl_invalidate_cache(struct file *filp,
				       struct xvp_ioctl_invalidate_cache __user *p)
{
	struct xvp_ioctl_invalidate_cache xvp_ioctl_invalidate_cache;

	pr_debug("%s: %p\n", __func__, p);

	if (copy_from_user(&xvp_ioctl_invalidate_cache, p, sizeof(*p)))
		return -EFAULT;

	return xvp_process_buffers(filp,
				   xvp_ioctl_invalidate_cache.num_addr,
				   (__u32 __user *)xvp_ioctl_invalidate_cache.addrs,
				   (__u32 __user *)xvp_ioctl_invalidate_cache.sizes,
				   xvp_share_from_core);
}

static long xvp_ioctl_free(struct file *filp,
			   struct xvp_ioctlx_alloc __user *p)
{
	struct mm_struct *mm = current->mm;
	struct xvp_ioctlx_alloc xvp_ioctlx_alloc;
	struct vm_area_struct *vma;
	unsigned long start;

	pr_debug("%s: %p\n", __func__, p);
	if (copy_from_user(&xvp_ioctlx_alloc, p, sizeof(*p)))
		return -EFAULT;

	start = xvp_ioctlx_alloc.virt_addr;
	pr_debug("%s: virt_addr = 0x%08lx\n", __func__, start);

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, start);

	if (vma && vma->vm_file == filp &&
	    vma->vm_start <= start && start < vma->vm_end) {
		size_t size;

		start = vma->vm_start;
		size = vma->vm_end - vma->vm_start;
		up_read(&mm->mmap_sem);
		pr_debug("%s: 0x%lx x %zu\n", __func__, start, size);
		return vm_munmap(start, size);
	}
	pr_debug("%s: no vma/bad vma for vaddr = 0x%08lx\n", __func__, start);
	up_read(&mm->mmap_sem);

	return -EINVAL;
}

static long xvp_complete_cmd_irq(struct xvp *xvp)
{
	long timeout = XVP_TIMEOUT_JIFFIES;

	do {
		u32 cmd;

		timeout = wait_for_completion_interruptible_timeout(&xvp->completion,
								    timeout);
		cmd = xvp_comm_read32(xvp, XVP_COMM_CMD);
		rmb();

		if (cmd == XVP_CMD_IDLE)
			return 0;
	} while (timeout > 0);

	if (timeout == 0)
		return -EBUSY;
	return timeout;
}

static long xvp_complete_cmd_poll(struct xvp *xvp)
{
	unsigned long deadline = jiffies + XVP_TIMEOUT_JIFFIES;

	do {
		u32 cmd = xvp_comm_read32(xvp, XVP_COMM_CMD);

		rmb();
		if (cmd == XVP_CMD_IDLE)
			return 0;
		schedule();
	} while (time_before(jiffies, deadline));

	return -EBUSY;
}

static long xvp_ioctl_submit_sync(struct file *filp,
				  struct xvp_ioctls_submit __user *p)
{
	struct xvp_file *xvp_file = filp->private_data;
	struct xvp *xvp = xvp_file->xvp;
	struct xvp_ioctls_submit xvp_ioctls_submit;
	unsigned long addr;
	void *buffer = NULL;
	long ret = -EBUSY;

	if (copy_from_user(&xvp_ioctls_submit, p, sizeof(*p)))
		return -EFAULT;

	if (xvp_share_block(filp, xvp_ioctls_submit.addr, &addr,
			    xvp_ioctls_submit.size) < 0) {
		pr_debug("%s: passing non-shared data, making local copy\n",
			 __func__);
		buffer = kmalloc(xvp_ioctls_submit.size, GFP_KERNEL);
		if (!buffer)
			return -ENOMEM;

		addr = __pa(buffer);

		if (copy_from_user(buffer, (void *)xvp_ioctls_submit.addr,
				   xvp_ioctls_submit.size)) {
			kfree(buffer);
			return -EFAULT;
		}
		xvp_clean_cache(buffer, addr, xvp_ioctls_submit.size);
	}

	mutex_lock(&xvp->comm_lock);

	/* write to registers */
	xvp_comm_write32(xvp, XVP_COMM_DATA, addr);
	xvp_comm_write32(xvp, XVP_COMM_SIZE, xvp_ioctls_submit.size);
	wmb();
	xvp_comm_write32(xvp, XVP_COMM_CMD, xvp_ioctls_submit.cmd);

	if (xvp->use_irq) {
		wmb();
		xvp_reg_write32(xvp, XVP_REG_IVP_IRQ(XVP_IVP_IRQ_NUM), 1);
		ret = xvp_complete_cmd_irq(xvp);
	} else {
		ret = xvp_complete_cmd_poll(xvp);
	}

	if (ret == 0) {
		u32 status = xvp_comm_read32(xvp, XVP_COMM_STATUS);

		if (put_user(status, &p->status))
			ret = -EFAULT;
		xvp_flush_cache((void *)xvp_ioctls_submit.addr, addr,
				xvp_ioctls_submit.size);
	} else if (ret == -EBUSY && firmware_reboot) {
		int rc;

		pr_debug("%s: restarting firmware...\n", __func__);
		rc = xvp_boot_firmware(xvp);
		if (rc < 0)
			ret = rc;
	}

	mutex_unlock(&xvp->comm_lock);

	if (buffer)
		kfree(buffer);

	return ret;
}

static long xvp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct vm_area_struct *vma;
	long retval;

	pr_debug("%s: %x\n", __func__, cmd);

	vma  = filp->private_data;
	retval = 0;

	switch(cmd){
	case XVP_IOCTLQ_GET_PADDR:
		retval = xvp_ioctl_virt_to_phys(filp,
						(struct xvp_ioctlq_get_paddr __user *)arg);
		break;

	case XVP_IOCTL_INVALIDATE_CACHE:
		retval = xvp_ioctl_invalidate_cache(filp,
						    (struct xvp_ioctl_invalidate_cache __user *)arg);
		break;

	case XVP_IOCTLX_ALLOC:
		retval = xvp_ioctl_alloc(filp,
					 (struct xvp_ioctlx_alloc __user *)arg);
		break;

	case XVP_IOCTLS_FREE:
		retval = xvp_ioctl_free(filp,
					(struct xvp_ioctlx_alloc __user *)arg);
		break;

	case XVP_IOCTLS_SUBMIT_SYNC:
		retval = xvp_ioctl_submit_sync(filp,
					       (struct xvp_ioctls_submit __user *)arg);
		break;

	default:
		return -ENOTTY;
	}
	return retval;
}

static void xvp_vm_open(struct vm_area_struct *vma)
{
	pr_debug("%s\n", __func__);
	xvp_allocation_get(vma->vm_private_data);
}

static void xvp_vm_close(struct vm_area_struct *vma)
{
	pr_debug("%s\n", __func__);
	xvp_allocation_put(vma->vm_private_data);
}

static const struct vm_operations_struct xvp_vm_ops = {
	.open = xvp_vm_open,
	.close = xvp_vm_close,
};

static int xvp_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int err;
	struct xvp_file *xvp_file = filp->private_data;
	unsigned long pfn = vma->vm_pgoff + (xvp_file->xvp->pmem >> PAGE_SHIFT);
	struct xvp_allocation *xvp_allocation;

	pr_debug("%s\n", __func__);
	err = remap_pfn_range(vma, vma->vm_start, pfn,
			      vma->vm_end - vma->vm_start,
			      vma->vm_page_prot);

	xvp_allocation = xvp_allocation_dequeue(filp->private_data, pfn << PAGE_SHIFT);

	vma->vm_private_data = xvp_allocation;
	vma->vm_ops = &xvp_vm_ops;

	return err;
}

static int xvp_open(struct inode *inode, struct file *filp)
{
	struct xvp *xvp = container_of(filp->private_data,
				       struct xvp, miscdev);
	struct xvp_file *xvp_file =
		devm_kzalloc(xvp->dev, sizeof(*xvp_file), GFP_KERNEL);

	pr_debug("%s\n", __func__);
	if (!xvp_file)
		return -ENOMEM;

	xvp_file->xvp = xvp;
	spin_lock_init(&xvp_file->busy_list_lock);
	mutex_init(&xvp_file->alien_list_lock);
	filp->private_data = xvp_file;
	return 0;
}

static int xvp_close(struct inode *inode, struct file *filp)
{
	struct xvp_file *xvp_file = filp->private_data;

	pr_debug("%s\n", __func__);

	xvp_alien_lock(xvp_file);

	while (xvp_file->alien_list) {
		struct xvp_alien_mapping *cur = xvp_file->alien_list;

		pr_debug("%s: 0x%08lx x %ld\n", __func__, cur->vaddr, cur->size);
		xvp_file->alien_list = cur->next;
		xvp_alien_mapping_destroy(cur);
	}
	xvp_alien_unlock(xvp_file);

	devm_kfree(xvp_file->xvp->dev, xvp_file);
	return 0;
}

static void xvp_reset_dsp(struct xvp *xvp)
{
	xvp_reg_write32(xvp, XVP_REG_RESET, 1);
	udelay(1);
	xvp_reg_write32(xvp, XVP_REG_RESET, 0);
}

static void xvp_halt_dsp(struct xvp *xvp)
{
	xvp_reg_write32(xvp, XVP_REG_RUNSTALL, 1);
}

static void xvp_release_dsp(struct xvp *xvp)
{
	xvp_reg_write32(xvp, XVP_REG_RUNSTALL, 0);
}

static int xvp_load_firmware(struct xvp *xvp)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)xvp->firmware->data;
	int i;

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
		dev_err(xvp->dev, "bad firmware ELF magic\n");
		return -EINVAL;
	}

	if (ehdr->e_type != ET_EXEC) {
		dev_err(xvp->dev, "bad firmware ELF type\n");
		return -EINVAL;
	}

	if (ehdr->e_machine != 94 /*EM_XTENSA*/) {
		dev_err(xvp->dev, "bad firmware ELF machine\n");
		return -EINVAL;
	}

	if (ehdr->e_phoff >= xvp->firmware->size ||
	    ehdr->e_phoff +
	    ehdr->e_phentsize * ehdr->e_phnum > xvp->firmware->size) {
		dev_err(xvp->dev, "bad firmware ELF PHDR information\n");
		return -EINVAL;
	}

	xvp_halt_dsp(xvp);
	xvp_reset_dsp(xvp);

	for (i = 0; i < ehdr->e_phnum; ++i) {
		Elf32_Phdr *phdr = (void *)xvp->firmware->data +
			ehdr->e_phoff + i * ehdr->e_phentsize;
		void __iomem *p;

		/* Only load non-empty loadable segments, R/W/X */
		if (!(phdr->p_type == PT_LOAD &&
		      (phdr->p_flags & (PF_X | PF_R | PF_W)) &&
		      phdr->p_memsz > 0))
			continue;

		if (phdr->p_offset >= xvp->firmware->size ||
		    phdr->p_offset + phdr->p_filesz > xvp->firmware->size) {
			dev_err(xvp->dev,
				"bad firmware ELF program header entry %d\n",
				i);
			return -EINVAL;
		}

		dev_dbg(xvp->dev, "loading segment %d to physical 0x%08x\n",
			i, (u32)phdr->p_paddr);
		p = ioremap(phdr->p_paddr, phdr->p_memsz);
		if (!p) {
			dev_err(xvp->dev,
				"couldn't ioremap 0x%08x x 0x%08x\n",
				(u32)phdr->p_paddr, (u32)phdr->p_memsz);
			return -EINVAL;
		}
		memcpy_toio(p, (void *)xvp->firmware->data + phdr->p_offset,
			    ALIGN(phdr->p_filesz, 4));
		memset_io(p + ALIGN(phdr->p_filesz, 4), 0,
			  ALIGN(phdr->p_memsz - ALIGN(phdr->p_filesz, 4), 4));
		iounmap(p);
	}

	return 0;
}

static int xvp_request_firmware(struct xvp *xvp)
{
	int ret = request_firmware(&xvp->firmware, FIRMWARE_NAME, xvp->dev);

	if (ret < 0)
		return ret;

	ret = xvp_load_firmware(xvp);
	if (ret < 0) {
		release_firmware(xvp->firmware);
	}
	return ret;
}

static int xvp_boot_firmware(struct xvp *xvp)
{
	int ret;

	ret = xvp_request_firmware(xvp);
	if (ret < 0)
		return ret;

	xvp_comm_write32(xvp, XVP_COMM_CMD, XVP_CMD_IDLE);
	xvp_release_dsp(xvp);

	ret = xvp_synchronize(xvp);
	if (ret < 0) {
		xvp_halt_dsp(xvp);
		pr_err("%s: couldn't synchronize with IVP core\n", __func__);
		return ret;
	}
	return 0;
}

static const struct file_operations xvp_fops = {
	.owner  = THIS_MODULE,
	.llseek = no_llseek,
	.unlocked_ioctl = xvp_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = xvp_compat_ioctl,
#endif
	.mmap = xvp_mmap,
	.open = xvp_open,
	.release = xvp_close,
};

static int xvp_probe(struct platform_device *pdev)
{
	struct xvp *xvp;
	int ret;
	struct resource *mem;
	int irq;
	char nodename[sizeof("xvp") + 3 * sizeof(int)] = "xvp";

	xvp = devm_kzalloc(&pdev->dev, sizeof(*xvp), GFP_KERNEL);
	if (!xvp) {
		ret = -ENOMEM;
		goto err;
	}
	xvp->dev = &pdev->dev;
	platform_set_drvdata(pdev, xvp);
	mutex_init(&xvp->comm_lock);
	mutex_init(&xvp->free_list_lock);

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		ret = -ENODEV;
		goto err;
	}
	xvp->regs = devm_ioremap_resource(&pdev->dev, mem);
	pr_debug("%s: regs = %pap/%p\n", __func__, &mem->start, xvp->regs);

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!mem) {
		ret = -ENODEV;
		goto err;
	}
	xvp->comm = devm_ioremap_resource(&pdev->dev, mem);
	pr_debug("%s: comm = %pap/%p\n", __func__, &mem->start, xvp->comm);

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	if (!mem) {
		ret = -ENODEV;
		goto err;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq >= 0) {
		pr_debug("%s: irq = %d", __func__, irq);
		xvp->use_irq = true;
		init_completion(&xvp->completion);
		ret = devm_request_irq(&pdev->dev, irq, xvp_irq_handler,
				       IRQF_SHARED, pdev->name, xvp);
		if (ret < 0) {
			dev_err(&pdev->dev, "request_irq %d failed\n", irq);
			goto err;
		}
	} else {
		dev_info(xvp->dev, "no IRQ resource, using polling mode\n");
	}

	xvp->pmem = mem->start;
	xvp->free_list = kzalloc(sizeof(struct xvp_allocation), GFP_KERNEL);
	if (!xvp->free_list) {
		ret = -ENOMEM;
		goto err;
	}
	xvp->free_list->start = mem->start;
	xvp->free_list->size = resource_size(mem);
	pr_debug("%s: xvp->pmem = %pap\n", __func__, &xvp->pmem);

	xvp_reset_dsp(xvp);

	ret = xvp_boot_firmware(xvp);
	if (ret < 0)
		goto err_free;

	if (xvp_nodeid++)
		sprintf(nodename, "xvp%u", xvp_nodeid - 1);

	xvp->miscdev = (struct miscdevice){
		.minor = MISC_DYNAMIC_MINOR,
		.name = "xvp",
		.nodename = devm_kstrdup(&pdev->dev, nodename, GFP_KERNEL),
		.fops = &xvp_fops,
	};

	ret = misc_register(&xvp->miscdev);
	if (ret < 0)
		goto err_free;
	return 0;
err_free:
	kfree(xvp->free_list);
err:
	dev_err(&pdev->dev, "%s: ret = %d\n", __func__, ret);
	return ret;
}

static int xvp_remove(struct platform_device *pdev)
{
	struct xvp *xvp = platform_get_drvdata(pdev);

	xvp_halt_dsp(xvp);
	misc_deregister(&xvp->miscdev);
	release_firmware(xvp->firmware);
	kfree(xvp->free_list);
	--xvp_nodeid;
	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id xvp_match[] = {
	{ .compatible = "cdns,xvp", },
	{},
};
MODULE_DEVICE_TABLE(of, xvp_match);
#endif

static struct platform_driver xvp_driver = {
	.probe   = xvp_probe,
	.remove  = xvp_remove,
	.driver  = {
		.name = DRIVER_NAME,
		.of_match_table = of_match_ptr(xvp_match),
	},
};

module_platform_driver(xvp_driver);

MODULE_AUTHOR("Takayuki Sugawara");
MODULE_AUTHOR("Max Filippov");
MODULE_DESCRIPTION("XVP: Linux device driver for OpenVX APK");
MODULE_LICENSE("GPL v2");
