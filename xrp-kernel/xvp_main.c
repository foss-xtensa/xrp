/*
 * XRP: Linux device driver for Xtensa Remote Processing
 *
 * Copyright (c) 2015 - 2017 Cadence Design Systems, Inc.
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

#include <linux/acpi.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/property.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/mman.h>
#include <asm/uaccess.h>
#include "xrp_cma_alloc.h"
#include "xrp_firmware.h"
#include "xrp_hw.h"
#include "xrp_internal.h"
#include "xrp_kernel_defs.h"
#include "xrp_kernel_dsp_interface.h"
#include "xrp_private_alloc.h"

#define DRIVER_NAME "xrp"
#define XRP_DEFAULT_TIMEOUT 10

#ifndef __io_virt
#define __io_virt(a) ((void __force *)(a))
#endif

struct xrp_alien_mapping {
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

struct xrp_mapping {
	enum {
		XRP_MAPPING_NONE,
		XRP_MAPPING_NATIVE,
		XRP_MAPPING_ALIEN,
		XRP_MAPPING_KERNEL = 0x4,
	} type;
	union {
		struct {
			struct xrp_allocation *xrp_allocation;
			unsigned long vaddr;
		} native;
		struct xrp_alien_mapping alien_mapping;
	};
};

struct xvp_file {
	struct xvp *xvp;
	spinlock_t busy_list_lock;
	struct xrp_allocation *busy_list;
};

struct xrp_known_file {
	void *filp;
	struct hlist_node node;
};

static int firmware_command_timeout = XRP_DEFAULT_TIMEOUT;
module_param(firmware_command_timeout, int, 0644);
MODULE_PARM_DESC(firmware_command_timeout, "Firmware command timeout in seconds.");

static int firmware_reboot = 1;
module_param(firmware_reboot, int, 0644);
MODULE_PARM_DESC(firmware_reboot, "Reboot firmware on command timeout.");

enum {
	LOOPBACK_NORMAL,	/* normal work mode */
	LOOPBACK_NOIO,		/* don't communicate with FW, but still load it and control DSP */
	LOOPBACK_NOMMIO,	/* don't comminicate with FW or use DSP MMIO, but still load the FW */
	LOOPBACK_NOFIRMWARE,	/* don't communicate with FW or use DSP MMIO, don't load the FW */
};
static int loopback = 0;
module_param(loopback, int, 0644);
MODULE_PARM_DESC(loopback, "Don't use actual DSP, perform everything locally.");

static DEFINE_HASHTABLE(xrp_known_files, 10);
static DEFINE_SPINLOCK(xrp_known_files_lock);

static DEFINE_IDA(xvp_nodeid);

static int xrp_boot_firmware(struct xvp *xvp);

static bool xrp_cacheable(struct xvp *xvp, unsigned long pfn,
			  unsigned long n_pages)
{
	if (xvp->hw_ops->cacheable) {
		return xvp->hw_ops->cacheable(xvp->hw_arg, pfn, n_pages);
	} else {
		unsigned long i;

		for (i = 0; i < n_pages; ++i)
			if (!pfn_valid(pfn + i))
				return false;
		return true;
	}
}

static int xrp_dma_direction(unsigned flags)
{
	static const enum dma_data_direction xrp_dma_direction[] = {
		[0] = DMA_NONE,
		[XRP_FLAG_READ] = DMA_TO_DEVICE,
		[XRP_FLAG_WRITE] = DMA_FROM_DEVICE,
		[XRP_FLAG_READ_WRITE] = DMA_BIDIRECTIONAL,
	};
	return xrp_dma_direction[flags & XRP_FLAG_READ_WRITE];
}

static void xrp_default_dma_sync_for_device(struct xvp *xvp,
					    phys_addr_t phys,
					    unsigned long size,
					    unsigned long flags)
{
	dma_sync_single_for_device(xvp->dev, phys_to_dma(xvp->dev, phys), size,
				   xrp_dma_direction(flags));
}

static void xrp_dma_sync_for_device(struct xvp *xvp,
				    unsigned long virt,
				    phys_addr_t phys,
				    unsigned long size,
				    unsigned long flags)
{
	if (xvp->hw_ops->dma_sync_for_device)
		xvp->hw_ops->dma_sync_for_device(xvp->hw_arg,
						 (void *)virt, phys, size,
						 flags);
	else
		xrp_default_dma_sync_for_device(xvp, phys, size, flags);
}

static void xrp_default_dma_sync_for_cpu(struct xvp *xvp,
					 phys_addr_t phys,
					 unsigned long size,
					 unsigned long flags)
{
	dma_sync_single_for_cpu(xvp->dev, phys_to_dma(xvp->dev, phys), size,
				xrp_dma_direction(flags));
}

static void xrp_dma_sync_for_cpu(struct xvp *xvp,
				 unsigned long virt,
				 phys_addr_t phys,
				 unsigned long size,
				 unsigned long flags)
{
	if (xvp->hw_ops->dma_sync_for_cpu)
		xvp->hw_ops->dma_sync_for_cpu(xvp->hw_arg,
					      (void *)virt, phys, size,
					      flags);
	else
		xrp_default_dma_sync_for_cpu(xvp, phys, size, flags);
}

static inline void xrp_comm_write32(volatile void __iomem *addr, u32 v)
{
	__raw_writel(v, addr);
}

static inline u32 xrp_comm_read32(volatile void __iomem *addr)
{
	return __raw_readl(addr);
}

static inline void xrp_comm_write(volatile void __iomem *addr, const void *p,
				  size_t sz)
{
	size_t sz32 = sz & ~3;
	u32 v;

	while (sz32) {
		memcpy(&v, p, sizeof(v));
		__raw_writel(v, addr);
		p += 4;
		addr += 4;
		sz32 -= 4;
	}
	sz &= 3;
	if (sz) {
		v = 0;
		memcpy(&v, p, sz);
		__raw_writel(v, addr);
	}
}

static inline void xrp_comm_read(volatile void __iomem *addr, void *p,
				  size_t sz)
{
	size_t sz32 = sz & ~3;
	u32 v;

	while (sz32) {
		v = __raw_readl(addr);
		memcpy(p, &v, sizeof(v));
		p += 4;
		addr += 4;
		sz32 -= 4;
	}
	sz &= 3;
	if (sz) {
		v = __raw_readl(addr);
		memcpy(p, &v, sz);
	}
}

static inline void xrp_send_device_irq(struct xvp *xvp)
{
	if (xvp->hw_ops->send_irq)
		xvp->hw_ops->send_irq(xvp->hw_arg);
}

static inline bool xrp_panic_check(struct xvp *xvp)
{
	if (xvp->hw_ops->panic_check)
		return xvp->hw_ops->panic_check(xvp->hw_arg);
	else
		return false;
}

static void xrp_add_known_file(struct file *filp)
{
	struct xrp_known_file *p = kmalloc(sizeof(*p), GFP_KERNEL);

	if (!p)
		return;

	p->filp = filp;
	spin_lock(&xrp_known_files_lock);
	hash_add(xrp_known_files, &p->node, (unsigned long)filp);
	spin_unlock(&xrp_known_files_lock);
}

static void xrp_remove_known_file(struct file *filp)
{
	struct xrp_known_file *p;
	struct xrp_known_file *pf = NULL;

	spin_lock(&xrp_known_files_lock);
	hash_for_each_possible(xrp_known_files, p, node, (unsigned long)filp) {
		if (p->filp == filp) {
			hash_del(&p->node);
			pf = p;
			break;
		}
	}
	spin_unlock(&xrp_known_files_lock);
	if (pf)
		kfree(pf);
}

static bool xrp_is_known_file(struct file *filp)
{
	bool ret = false;
	struct xrp_known_file *p;

	spin_lock(&xrp_known_files_lock);
	hash_for_each_possible(xrp_known_files, p, node, (unsigned long)filp) {
		if (p->filp == filp) {
			ret = true;
			break;
		}
	}
	spin_unlock(&xrp_known_files_lock);
	return ret;
}

static int xrp_synchronize(struct xvp *xvp)
{
	size_t sz;
	void *hw_sync_data;
	unsigned long deadline = jiffies + firmware_command_timeout * HZ;
	struct xrp_dsp_sync __iomem *shared_sync = xvp->comm;
	int ret;
	u32 v;

	hw_sync_data = xvp->hw_ops->get_hw_sync_data(xvp->hw_arg, &sz);
	if (!hw_sync_data) {
		ret = -ENOMEM;
		goto err;
	}
	ret = -ENODEV;
	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_START);
	mb();
	do {
		v = xrp_comm_read32(&shared_sync->sync);
		if (v == XRP_DSP_SYNC_DSP_READY)
			break;
		if (xrp_panic_check(xvp))
			goto err;
		schedule();
	} while (time_before(jiffies, deadline));

	if (v != XRP_DSP_SYNC_DSP_READY) {
		dev_err(xvp->dev, "DSP is not ready for synchronization\n");
		goto err;
	}

	xrp_comm_write(&shared_sync->hw_sync_data, hw_sync_data, sz);
	mb();
	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_HOST_TO_DSP);
	mb();

	do {
		v = xrp_comm_read32(&shared_sync->sync);
		if (v == XRP_DSP_SYNC_DSP_TO_HOST)
			break;
		if (xrp_panic_check(xvp))
			goto err;
		schedule();
	} while (time_before(jiffies, deadline));

	if (v != XRP_DSP_SYNC_DSP_TO_HOST) {
		dev_err(xvp->dev,
			"DSP haven't confirmed initialization data reception\n");
		goto err;
	}

	xrp_send_device_irq(xvp);

	if (xvp->host_irq_mode) {
		int res = wait_for_completion_timeout(&xvp->completion,
						      firmware_command_timeout * HZ);
		if (xrp_panic_check(xvp))
			goto err;
		if (res == 0) {
			dev_err(xvp->dev,
				"host IRQ mode is requested, but DSP couldn't deliver IRQ during synchronization\n");
			goto err;
		}
	}
	ret = 0;
err:
	kfree(hw_sync_data);
	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_IDLE);
	return ret;
}

static bool xrp_cmd_complete(struct xvp *xvp)
{
	struct xrp_dsp_cmd __iomem *cmd = xvp->comm;
	u32 flags = xrp_comm_read32(&cmd->flags);

	rmb();
	return (flags & (XRP_DSP_CMD_FLAG_REQUEST_VALID |
			 XRP_DSP_CMD_FLAG_RESPONSE_VALID)) ==
		(XRP_DSP_CMD_FLAG_REQUEST_VALID |
		 XRP_DSP_CMD_FLAG_RESPONSE_VALID);
}

irqreturn_t xrp_irq_handler(int irq, struct xvp *xvp)
{
	if (!xvp->comm || !xrp_cmd_complete(xvp))
		return IRQ_NONE;

	complete(&xvp->completion);

	return IRQ_HANDLED;
}
EXPORT_SYMBOL(xrp_irq_handler);

static inline void xvp_file_lock(struct xvp_file *xvp_file)
{
	spin_lock(&xvp_file->busy_list_lock);
}

static inline void xvp_file_unlock(struct xvp_file *xvp_file)
{
	spin_unlock(&xvp_file->busy_list_lock);
}

static void xrp_allocation_queue(struct xvp_file *xvp_file,
				 struct xrp_allocation *xrp_allocation)
{
	xvp_file_lock(xvp_file);

	xrp_allocation->next = xvp_file->busy_list;
	xvp_file->busy_list = xrp_allocation;

	xvp_file_unlock(xvp_file);
}

static struct xrp_allocation *xrp_allocation_dequeue(struct xvp_file *xvp_file,
						     phys_addr_t paddr, u32 size)
{
	struct xrp_allocation **pcur;
	struct xrp_allocation *cur;

	xvp_file_lock(xvp_file);

	for (pcur = &xvp_file->busy_list; (cur = *pcur); pcur = &((*pcur)->next)) {
		pr_debug("%s: %pap / %pap x %d\n", __func__, &paddr, &cur->start, cur->size);
		if (paddr >= cur->start && paddr + size - cur->start <= cur->size) {
			*pcur = cur->next;
			break;
		}
	}

	xvp_file_unlock(xvp_file);
	return cur;
}

static long xrp_ioctl_alloc(struct file *filp,
			    struct xrp_ioctl_alloc __user *p)
{
	struct xvp_file *xvp_file = filp->private_data;
	struct xrp_allocation *xrp_allocation;
	unsigned long vaddr;
	struct xrp_ioctl_alloc xrp_ioctl_alloc;
	long err;

	pr_debug("%s: %p\n", __func__, p);
	if (copy_from_user(&xrp_ioctl_alloc, p, sizeof(*p)))
		return -EFAULT;

	pr_debug("%s: size = %d, align = %x\n", __func__,
		 xrp_ioctl_alloc.size, xrp_ioctl_alloc.align);

	err = xrp_allocate(xvp_file->xvp->pool,
			   xrp_ioctl_alloc.size,
			   xrp_ioctl_alloc.align,
			   &xrp_allocation);
	if (err)
		return err;

	xrp_allocation_queue(xvp_file, xrp_allocation);

	vaddr = vm_mmap(filp, 0, xrp_allocation->size,
			PROT_READ | PROT_WRITE, MAP_SHARED,
			xrp_allocation_offset(xrp_allocation));

	xrp_ioctl_alloc.addr = vaddr;

	if (copy_to_user(p, &xrp_ioctl_alloc, sizeof(*p))) {
		vm_munmap(vaddr, xrp_ioctl_alloc.size);
		return -EFAULT;
	}
	return 0;
}

static void xrp_put_pages(phys_addr_t phys, unsigned long n_pages)
{
	struct page *page;
	unsigned long i;

	page = pfn_to_page(__phys_to_pfn(phys));
	for (i = 0; i < n_pages; ++i)
		put_page(page + i);
}

static void xrp_alien_mapping_destroy(struct xrp_alien_mapping *alien_mapping)
{
	switch (alien_mapping->type) {
	case ALIEN_GUP:
		xrp_put_pages(alien_mapping->paddr,
			      PFN_UP(alien_mapping->vaddr +
				     alien_mapping->size) -
			      PFN_DOWN(alien_mapping->vaddr));
		break;
	case ALIEN_COPY:
		xrp_allocation_put(alien_mapping->allocation);
		break;
	default:
		break;
	}
}

static long xvp_pfn_virt_to_phys(struct xvp_file *xvp_file,
				 struct vm_area_struct *vma,
				 unsigned long vaddr, unsigned long size,
				 phys_addr_t *paddr,
				 struct xrp_alien_mapping *mapping)
{
	int i;
	int ret;
	int nr_pages = PFN_UP(vaddr + size) - PFN_DOWN(vaddr);
	unsigned long pfn;
	const struct xrp_address_map_entry *address_map;

	ret = follow_pfn(vma, vaddr, &pfn);
	if (ret)
		return ret;

	*paddr = __pfn_to_phys(pfn) + (vaddr & ~PAGE_MASK);
	address_map = xrp_get_address_mapping(&xvp_file->xvp->address_map,
					      *paddr);
	if (!address_map) {
		pr_debug("%s: untranslatable addr: %pap\n", __func__, paddr);
		return -EINVAL;
	}

	for (i = 1; i < nr_pages; ++i) {
		unsigned long next_pfn;
		phys_addr_t next_phys;

		ret = follow_pfn(vma, vaddr + (i << PAGE_SHIFT), &next_pfn);
		if (ret)
			return ret;
		if (next_pfn != pfn + 1) {
			pr_debug("%s: non-contiguous physical memory\n",
				 __func__);
			return -EINVAL;
		}
		next_phys = __pfn_to_phys(next_pfn);
		if (xrp_compare_address(next_phys, address_map)) {
			pr_debug("%s: untranslatable addr: %pap\n",
				 __func__, &next_phys);
			return -EINVAL;
		}
		pfn = next_pfn;
	}
	*mapping = (struct xrp_alien_mapping){
		.vaddr = vaddr,
		.size = size,
		.paddr = *paddr,
		.type = ALIEN_PFN_MAP,
	};
	pr_debug("%s: success, paddr: %pap\n", __func__, paddr);
	return 0;
}

static long xvp_gup_virt_to_phys(struct xvp_file *xvp_file,
				 unsigned long vaddr, unsigned long size,
				 phys_addr_t *paddr,
				 struct xrp_alien_mapping *mapping)
{
	int ret;
	int i;
	int nr_pages = PFN_UP(vaddr + size) - PFN_DOWN(vaddr);
	struct page **page = kmalloc(nr_pages * sizeof(void *), GFP_KERNEL);
	const struct xrp_address_map_entry *address_map;

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

	address_map = xrp_get_address_mapping(&xvp_file->xvp->address_map,
					      page_to_phys(page[0]));
	if (!address_map) {
		phys_addr_t addr = page_to_phys(page[0]);
		pr_debug("%s: untranslatable addr: %pap\n",
			 __func__, &addr);
		ret = -EINVAL;
		goto out_put;
	}

	for (i = 1; i < nr_pages; ++i) {
		phys_addr_t addr;

		if (page[i] != page[i - 1] + 1) {
			pr_debug("%s: non-contiguous physical memory\n",
				 __func__);
			ret = -EINVAL;
			goto out_put;
		}
		addr = page_to_phys(page[i]);
		if (xrp_compare_address(addr, address_map)) {
			pr_debug("%s: untranslatable addr: %pap\n",
				 __func__, &addr);
			ret = -EINVAL;
			goto out_put;
		}
	}

	*paddr = __pfn_to_phys(page_to_pfn(page[0])) + (vaddr & ~PAGE_MASK);
	*mapping = (struct xrp_alien_mapping){
		.vaddr = vaddr,
		.size = size,
		.paddr = *paddr,
		.type = ALIEN_GUP,
	};
	ret = 0;
	pr_debug("%s: success, paddr: %pap\n", __func__, paddr);

out_put:
	if (ret < 0)
		for (i = 0; i < nr_pages; ++i)
			put_page(page[i]);
out:
	kfree(page);
	return ret;
}

static long _xrp_copy_user_phys(struct xvp *xvp,
				unsigned long vaddr, unsigned long size,
				phys_addr_t paddr, unsigned long flags,
				bool to_phys)
{
	if (pfn_valid(__phys_to_pfn(paddr))) {
		struct page *page = pfn_to_page(__phys_to_pfn(paddr));
		size_t page_offs = paddr & ~PAGE_MASK;
		size_t offs;

		if (!to_phys)
			xrp_default_dma_sync_for_cpu(xvp, paddr, size, flags);
		for (offs = 0; offs < size; ++page) {
			void *p = kmap(page);
			size_t sz = PAGE_SIZE - page_offs;
			size_t copy_sz = sz;
			unsigned long rc;

			if (!p)
				return -ENOMEM;

			if (size - offs < copy_sz)
				copy_sz = size - offs;

			if (to_phys)
				rc = copy_from_user(p + page_offs,
						    (void __user *)(vaddr + offs),
						    copy_sz);
			else
				rc = copy_to_user((void __user *)(vaddr + offs),
						  p + page_offs, copy_sz);

			page_offs = 0;
			offs += copy_sz;

			kunmap(page);
			if (rc)
				return -EFAULT;
		}
		if (to_phys)
			xrp_default_dma_sync_for_device(xvp, paddr, size, flags);
	} else {
		void __iomem *p = ioremap(paddr, size);
		unsigned long rc;

		if (!p) {
			dev_err(xvp->dev,
				"couldn't ioremap %pap x 0x%08x\n",
				&paddr, (u32)size);
			return -EINVAL;
		}
		if (to_phys)
			rc = copy_from_user(__io_virt(p),
					    (void __user *)vaddr, size);
		else
			rc = copy_to_user((void __user *)vaddr,
					  __io_virt(p), size);
		iounmap(p);
		if (rc)
			return -EFAULT;
	}
	return 0;
}

static long xrp_copy_user_to_phys(struct xvp *xvp,
				  unsigned long vaddr, unsigned long size,
				  phys_addr_t paddr, unsigned long flags)
{
	return _xrp_copy_user_phys(xvp, vaddr, size, paddr, flags, true);
}

static long xrp_copy_user_from_phys(struct xvp *xvp,
				    unsigned long vaddr, unsigned long size,
				    phys_addr_t paddr, unsigned long flags)
{
	return _xrp_copy_user_phys(xvp, vaddr, size, paddr, flags, false);
}

static long xvp_copy_virt_to_phys(struct xvp_file *xvp_file,
				  unsigned long flags,
				  unsigned long vaddr, unsigned long size,
				  phys_addr_t *paddr,
				  struct xrp_alien_mapping *mapping)
{
	phys_addr_t phys;
	unsigned long align = clamp(vaddr & -vaddr, 16ul, PAGE_SIZE);
	unsigned long offset = vaddr & (align - 1);
	struct xrp_allocation *allocation;
	long rc;

	rc = xrp_allocate(xvp_file->xvp->pool,
			  size + align, align, &allocation);
	if (rc < 0)
		return rc;

	phys = (allocation->start & -align) | offset;
	if (phys < allocation->start)
		phys += align;

	if (flags & XRP_FLAG_READ) {
		if (xrp_copy_user_to_phys(xvp_file->xvp,
					  vaddr, size, phys, flags)) {
			xrp_allocation_put(allocation);
			return -EFAULT;
		}
	}

	*paddr = phys;
	*mapping = (struct xrp_alien_mapping){
		.vaddr = vaddr,
		.size = size,
		.paddr = *paddr,
		.allocation = allocation,
		.type = ALIEN_COPY,
	};
	pr_debug("%s: copying to pa: %pap\n", __func__, paddr);

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

static long xrp_share_kernel(struct file *filp,
			     unsigned long virt, unsigned long size,
			     unsigned long flags, phys_addr_t *paddr,
			     struct xrp_mapping *mapping)
{
	struct xvp_file *xvp_file = filp->private_data;
	struct xvp *xvp = xvp_file->xvp;
	phys_addr_t phys = __pa(virt);
	long err = 0;

	pr_debug("%s: sharing kernel-only buffer: %pap\n", __func__, &phys);
	if (xrp_translate_to_dsp(&xvp->address_map, phys) ==
	    XRP_NO_TRANSLATION) {
		mm_segment_t oldfs = get_fs();

		pr_debug("%s: untranslatable addr, making shadow copy\n",
			 __func__);
	        set_fs(KERNEL_DS);
		err = xvp_copy_virt_to_phys(xvp_file, flags,
					    virt, size, paddr,
					    &mapping->alien_mapping);
		set_fs(oldfs);
		mapping->type = XRP_MAPPING_ALIEN | XRP_MAPPING_KERNEL;
	} else {
		mapping->type = XRP_MAPPING_KERNEL;
		*paddr = phys;

		xrp_default_dma_sync_for_device(xvp, phys, size, flags);
	}
	pr_debug("%s: mapping = %p, mapping->type = %d\n",
		 __func__, mapping, mapping->type);
	return err;
}

static bool vma_needs_cache_ops(struct vm_area_struct *vma)
{
	pgprot_t prot = vma->vm_page_prot;

	return pgprot_val(prot) != pgprot_val(pgprot_noncached(prot)) &&
		pgprot_val(prot) != pgprot_val(pgprot_writecombine(prot));
}

/* Share blocks of memory, from host to IVP or back.
 *
 * When sharing to IVP return physical addresses in paddr.
 * Areas allocated from the driver can always be shared in both directions.
 * Contiguous 3rd party allocations need to be shared to IVP before they can
 * be shared back.
 */

static long __xrp_share_block(struct file *filp,
			      unsigned long virt, unsigned long size,
			      unsigned long flags, phys_addr_t *paddr,
			      struct xrp_mapping *mapping)
{
	phys_addr_t phys = ~0ul;
	struct xvp_file *xvp_file = filp->private_data;
	struct xvp *xvp = xvp_file->xvp;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma = find_vma(mm, virt);
	bool do_cache = true;
	long rc = -EINVAL;

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
	 * And it need to be allocated from the same file descriptor, or
	 * at least from a file descriptor managed by the XRP.
	 */
	if (vma &&
	    (vma->vm_file == filp || xrp_is_known_file(vma->vm_file))) {
		struct xvp_file *vm_file = vma->vm_file->private_data;
		struct xrp_allocation *xrp_allocation = vma->vm_private_data;

		phys = vm_file->xvp->pmem + (vma->vm_pgoff << PAGE_SHIFT) +
			virt - vma->vm_start;
		pr_debug("%s: XRP allocation at 0x%08lx, paddr: %pap\n",
			 __func__, virt, &phys);
		/*
		 * If it was allocated from a different XRP file it may belong
		 * to a different device and not be directly accessible.
		 * Check if it is.
		 */
		if (vma->vm_file != filp) {
			const struct xrp_address_map_entry *address_map =
				xrp_get_address_mapping(&xvp->address_map,
							phys);

			if (!address_map ||
			    xrp_compare_address(phys + size - 1, address_map))
				pr_debug("%s: untranslatable addr: %pap\n",
					 __func__, &phys);
			else
				rc = 0;

		} else {
			rc = 0;
		}

		if (rc == 0) {
			mapping->type = XRP_MAPPING_NATIVE;
			mapping->native.xrp_allocation = xrp_allocation;
			mapping->native.vaddr = virt;
			xrp_allocation_get(xrp_allocation);
			do_cache = vma_needs_cache_ops(vma);
		}
	}
	if (rc < 0) {
		struct xrp_alien_mapping *alien_mapping =
			&mapping->alien_mapping;
		unsigned long n_pages = PFN_UP(virt + size) - PFN_DOWN(virt);

		/* Otherwise this is alien allocation. */
		pr_debug("%s: non-XVP allocation at 0x%08lx\n",
			 __func__, virt);

		/*
		 * A range can only be mapped directly if it is either
		 * uncached or HW-specific cache operations can handle it.
		 */
		if (vma && vma->vm_flags & (VM_IO | VM_PFNMAP)) {
			rc = xvp_pfn_virt_to_phys(xvp_file, vma,
						  virt, size,
						  &phys,
						  alien_mapping);
			if (rc == 0 && vma_needs_cache_ops(vma) &&
			    !xrp_cacheable(xvp, PFN_DOWN(phys), n_pages)) {
				pr_debug("%s: needs unsupported cache mgmt\n",
					 __func__);
				rc = -EINVAL;
			}
		} else {
			up_read(&mm->mmap_sem);
			rc = xvp_gup_virt_to_phys(xvp_file, virt,
						  size, &phys,
						  alien_mapping);
			if (rc == 0 &&
			    (!vma || vma_needs_cache_ops(vma)) &&
			    !xrp_cacheable(xvp, PFN_DOWN(phys), n_pages)) {
				pr_debug("%s: needs unsupported cache mgmt\n",
					 __func__);
				xrp_put_pages(phys, n_pages);
				rc = -EINVAL;
			}
			down_read(&mm->mmap_sem);
		}
		if (rc == 0 && vma && !vma_needs_cache_ops(vma))
			do_cache = false;

		/*
		 * If we couldn't share try to make a shadow copy.
		 */
		if (rc < 0) {
			rc = xvp_copy_virt_to_phys(xvp_file, flags,
						   virt, size, &phys,
						   alien_mapping);
			do_cache = false;
		}

		/* We couldn't share it. Fail the request. */
		if (rc < 0) {
			pr_debug("%s: couldn't map virt to phys\n",
				 __func__);
			return -EINVAL;
		}

		phys = alien_mapping->paddr +
			virt - alien_mapping->vaddr;

		mapping->type = XRP_MAPPING_ALIEN;
	}

	*paddr = phys;
	pr_debug("%s: mapping = %p, mapping->type = %d\n",
		 __func__, mapping, mapping->type);

	if (do_cache)
		xrp_dma_sync_for_device(xvp,
					virt, phys, size,
					flags);
	return 0;
}

static long xrp_writeback_alien_mapping(struct xvp_file *xvp_file,
					struct xrp_alien_mapping *alien_mapping,
					unsigned long flags)
{
	struct page *page;
	size_t nr_pages;
	size_t i;
	long ret = 0;

	switch (alien_mapping->type) {
	case ALIEN_GUP:
		xrp_dma_sync_for_cpu(xvp_file->xvp,
				     alien_mapping->vaddr,
				     alien_mapping->paddr,
				     alien_mapping->size,
				     flags);
		pr_debug("%s: dirtying alien GUP @va = %p, pa = %pap\n",
			 __func__, (void __user *)alien_mapping->vaddr,
			 &alien_mapping->paddr);
		page = pfn_to_page(__phys_to_pfn(alien_mapping->paddr));
		nr_pages = PFN_UP(alien_mapping->vaddr + alien_mapping->size) -
			PFN_DOWN(alien_mapping->vaddr);
		for (i = 0; i < nr_pages; ++i)
			SetPageDirty(page + i);
		break;

	case ALIEN_COPY:
		pr_debug("%s: synchronizing alien copy @pa = %pap back to %p\n",
			 __func__, &alien_mapping->paddr,
			 (void __user *)alien_mapping->vaddr);
		if (xrp_copy_user_from_phys(xvp_file->xvp,
					    alien_mapping->vaddr,
					    alien_mapping->size,
					    alien_mapping->paddr,
					    flags))
			ret = -EINVAL;
		break;

	default:
		break;
	}
	return ret;
}

/*
 *
 */
static long __xrp_unshare_block(struct file *filp, struct xrp_mapping *mapping,
				unsigned long flags)
{
	long ret = 0;
	mm_segment_t oldfs = get_fs();

	if (mapping->type & XRP_MAPPING_KERNEL)
	        set_fs(KERNEL_DS);

	switch (mapping->type & ~XRP_MAPPING_KERNEL) {
	case XRP_MAPPING_NATIVE:
		if (flags & XRP_FLAG_WRITE) {
			struct xvp_file *xvp_file = filp->private_data;

			xrp_dma_sync_for_cpu(xvp_file->xvp,
					     mapping->native.vaddr,
					     mapping->native.xrp_allocation->start,
					     mapping->native.xrp_allocation->size,
					     flags);

		}
		xrp_allocation_put(mapping->native.xrp_allocation);
		break;

	case XRP_MAPPING_ALIEN:
		if (flags & XRP_FLAG_WRITE)
			ret = xrp_writeback_alien_mapping(filp->private_data,
							  &mapping->alien_mapping,
							  flags);

		xrp_alien_mapping_destroy(&mapping->alien_mapping);
		break;

	case XRP_MAPPING_KERNEL:
		break;

	default:
		break;
	}

	if (mapping->type & XRP_MAPPING_KERNEL)
		set_fs(oldfs);

	mapping->type = XRP_MAPPING_NONE;

	return ret;
}

static long xrp_ioctl_free(struct file *filp,
			   struct xrp_ioctl_alloc __user *p)
{
	struct mm_struct *mm = current->mm;
	struct xrp_ioctl_alloc xrp_ioctl_alloc;
	struct vm_area_struct *vma;
	unsigned long start;

	pr_debug("%s: %p\n", __func__, p);
	if (copy_from_user(&xrp_ioctl_alloc, p, sizeof(*p)))
		return -EFAULT;

	start = xrp_ioctl_alloc.addr;
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

static long xvp_complete_cmd_irq(struct xvp *xvp,
				 struct completion *completion,
				 bool (*cmd_complete)(struct xvp *p))
{
	long timeout = firmware_command_timeout * HZ;

	if (cmd_complete(xvp))
		return 0;
	if (xrp_panic_check(xvp))
		return -EBUSY;
	do {
		timeout = wait_for_completion_interruptible_timeout(completion,
								    timeout);
		if (cmd_complete(xvp))
			return 0;
		if (xrp_panic_check(xvp))
			return -EBUSY;
	} while (timeout > 0);

	if (timeout == 0)
		return -EBUSY;
	return timeout;
}

static long xvp_complete_cmd_poll(struct xvp *xvp,
				  bool (*cmd_complete)(struct xvp *p))
{
	unsigned long deadline = jiffies + firmware_command_timeout * HZ;

	do {
		if (cmd_complete(xvp))
			return 0;
		if (xrp_panic_check(xvp))
			return -EBUSY;
		schedule();
	} while (time_before(jiffies, deadline));

	return -EBUSY;
}

struct xrp_request {
	struct xrp_ioctl_queue ioctl_queue;
	size_t n_buffers;
	struct xrp_mapping *buffer_mapping;
	struct xrp_dsp_buffer *dsp_buffer;
	phys_addr_t in_data_phys;
	phys_addr_t out_data_phys;
	phys_addr_t dsp_buffer_phys;
	union {
		struct xrp_mapping in_data_mapping;
		u8 in_data[XRP_DSP_CMD_INLINE_DATA_SIZE];
	};
	union {
		struct xrp_mapping out_data_mapping;
		u8 out_data[XRP_DSP_CMD_INLINE_DATA_SIZE];
	};
	union {
		struct xrp_mapping dsp_buffer_mapping;
		struct xrp_dsp_buffer buffer_data[XRP_DSP_CMD_INLINE_BUFFER_COUNT];
	};
	u8 nsid[XRP_DSP_CMD_NAMESPACE_ID_SIZE];
};

static void xrp_unmap_request_nowb(struct file *filp, struct xrp_request *rq)
{
	size_t n_buffers = rq->n_buffers;
	size_t i;

	if (rq->ioctl_queue.in_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE)
		__xrp_unshare_block(filp, &rq->in_data_mapping, 0);
	if (rq->ioctl_queue.out_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE)
		__xrp_unshare_block(filp, &rq->out_data_mapping, 0);
	for (i = 0; i < n_buffers; ++i)
		__xrp_unshare_block(filp, rq->buffer_mapping + i, 0);
	if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT)
		__xrp_unshare_block(filp, &rq->dsp_buffer_mapping, 0);

	if (n_buffers) {
		kfree(rq->buffer_mapping);
		if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
			kfree(rq->dsp_buffer);
		}
	}
}

static long xrp_unmap_request(struct file *filp, struct xrp_request *rq)
{
	size_t n_buffers = rq->n_buffers;
	size_t i;
	long ret = 0;
	long rc;

	if (rq->ioctl_queue.in_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE)
		__xrp_unshare_block(filp, &rq->in_data_mapping, XRP_FLAG_READ);
	if (rq->ioctl_queue.out_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		rc = __xrp_unshare_block(filp, &rq->out_data_mapping,
					 XRP_FLAG_WRITE);

		if (rc < 0) {
			pr_debug("%s: out_data could not be unshared\n",
				 __func__);
			ret = rc;
		}
	} else {
		if (copy_to_user((void __user *)(unsigned long)rq->ioctl_queue.out_data_addr,
				 rq->out_data,
				 rq->ioctl_queue.out_data_size)) {
			pr_debug("%s: out_data could not be copied\n",
				 __func__);
			ret = -EFAULT;
		}
	}

	if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT)
		__xrp_unshare_block(filp, &rq->dsp_buffer_mapping,
				    XRP_FLAG_READ_WRITE);

	for (i = 0; i < n_buffers; ++i) {
		rc = __xrp_unshare_block(filp, rq->buffer_mapping + i,
					 rq->dsp_buffer[i].flags);
		if (rc < 0) {
			pr_debug("%s: buffer %zd could not be unshared\n",
				 __func__, i);
			ret = rc;
		}
	}

	if (n_buffers) {
		kfree(rq->buffer_mapping);
		if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
			kfree(rq->dsp_buffer);
		}
		rq->n_buffers = 0;
	}

	return ret;
}

static long xrp_map_request(struct file *filp, struct xrp_request *rq,
			    struct mm_struct *mm)
{
	struct xvp_file *xvp_file = filp->private_data;
	struct xvp *xvp = xvp_file->xvp;
	struct xrp_ioctl_buffer __user *buffer;
	size_t n_buffers = rq->ioctl_queue.buffer_size /
		sizeof(struct xrp_ioctl_buffer);

	size_t i;
	long ret = 0;

	if ((rq->ioctl_queue.flags & XRP_QUEUE_FLAG_NSID) &&
	    copy_from_user(rq->nsid,
			   (void __user *)(unsigned long)rq->ioctl_queue.nsid_addr,
			   sizeof(rq->nsid))) {
		pr_debug("%s: nsid could not be copied\n ", __func__);
		return -EINVAL;
	}
	rq->n_buffers = n_buffers;
	if (n_buffers) {
		rq->buffer_mapping =
			kzalloc(n_buffers * sizeof(*rq->buffer_mapping),
				GFP_KERNEL);
		if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
			rq->dsp_buffer =
				kmalloc(n_buffers * sizeof(*rq->dsp_buffer),
					GFP_KERNEL);
			if (!rq->dsp_buffer) {
				kfree(rq->buffer_mapping);
				return -ENOMEM;
			}
		} else {
			rq->dsp_buffer = rq->buffer_data;
		}
	}

	down_read(&mm->mmap_sem);

	if (rq->ioctl_queue.in_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		ret = __xrp_share_block(filp, rq->ioctl_queue.in_data_addr,
					rq->ioctl_queue.in_data_size,
					XRP_FLAG_READ, &rq->in_data_phys,
					&rq->in_data_mapping);
		if(ret < 0) {
			pr_debug("%s: in_data could not be shared\n",
				 __func__);
			goto share_err;
		}
	} else {
		if (copy_from_user(rq->in_data,
				   (void __user *)(unsigned long)rq->ioctl_queue.in_data_addr,
				   rq->ioctl_queue.in_data_size)) {
			pr_debug("%s: in_data could not be copied\n",
				 __func__);
			ret = -EFAULT;
			goto share_err;
		}
	}

	if (rq->ioctl_queue.out_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		ret = __xrp_share_block(filp, rq->ioctl_queue.out_data_addr,
					rq->ioctl_queue.out_data_size,
					XRP_FLAG_WRITE, &rq->out_data_phys,
					&rq->out_data_mapping);
		if (ret < 0) {
			pr_debug("%s: out_data could not be shared\n",
				 __func__);
			goto share_err;
		}
	}

	buffer = (void __user *)(unsigned long)rq->ioctl_queue.buffer_addr;

	for (i = 0; i < n_buffers; ++i) {
		struct xrp_ioctl_buffer ioctl_buffer;
		phys_addr_t buffer_phys = ~0ul;

		if (copy_from_user(&ioctl_buffer, buffer + i,
				   sizeof(ioctl_buffer))) {
			ret = -EFAULT;
			goto share_err;
		}
		if (ioctl_buffer.flags & XRP_FLAG_READ_WRITE) {
			ret = __xrp_share_block(filp, ioctl_buffer.addr,
						ioctl_buffer.size,
						ioctl_buffer.flags,
						&buffer_phys,
						rq->buffer_mapping + i);
			if (ret < 0) {
				pr_debug("%s: buffer %zd could not be shared\n",
					 __func__, i);
				goto share_err;
			}
		}

		rq->dsp_buffer[i] = (struct xrp_dsp_buffer){
			.flags = ioctl_buffer.flags,
			.size = ioctl_buffer.size,
			.addr = xrp_translate_to_dsp(&xvp->address_map,
						     buffer_phys),
		};
	}

	if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
		ret = xrp_share_kernel(filp, (unsigned long)rq->dsp_buffer,
				       n_buffers * sizeof(*rq->dsp_buffer),
				       XRP_FLAG_READ_WRITE, &rq->dsp_buffer_phys,
				       &rq->dsp_buffer_mapping);
		if(ret < 0) {
			pr_debug("%s: buffer descriptors could not be shared\n",
				 __func__);
			goto share_err;
		}
	}
share_err:
	up_read(&mm->mmap_sem);
	if (ret < 0)
		xrp_unmap_request_nowb(filp, rq);
	return ret;
}

static void xrp_fill_hw_request(struct xrp_dsp_cmd __iomem *cmd,
				struct xrp_request *rq,
				const struct xrp_address_map *map)
{
	xrp_comm_write32(&cmd->in_data_size, rq->ioctl_queue.in_data_size);
	xrp_comm_write32(&cmd->out_data_size, rq->ioctl_queue.out_data_size);
	xrp_comm_write32(&cmd->buffer_size,
			 rq->n_buffers * sizeof(struct xrp_dsp_buffer));

	if (rq->ioctl_queue.in_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE)
		xrp_comm_write32(&cmd->in_data_addr,
				 xrp_translate_to_dsp(map, rq->in_data_phys));
	else
		xrp_comm_write(&cmd->in_data, rq->in_data,
			       rq->ioctl_queue.in_data_size);

	if (rq->ioctl_queue.out_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE)
		xrp_comm_write32(&cmd->out_data_addr,
				 xrp_translate_to_dsp(map, rq->out_data_phys));

	if (rq->n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT)
		xrp_comm_write32(&cmd->buffer_addr,
				 xrp_translate_to_dsp(map, rq->dsp_buffer_phys));
	else
		xrp_comm_write(&cmd->buffer_data, rq->dsp_buffer,
			       rq->n_buffers * sizeof(struct xrp_dsp_buffer));

	if (rq->ioctl_queue.flags & XRP_QUEUE_FLAG_NSID)
		xrp_comm_write(&cmd->nsid, rq->nsid, sizeof(rq->nsid));

#ifdef DEBUG
	{
		struct xrp_dsp_cmd dsp_cmd;
		xrp_comm_read(cmd, &dsp_cmd, sizeof(dsp_cmd));
		pr_debug("%s: cmd for DSP: %*ph\n",
			 __func__, (int)sizeof(dsp_cmd), &dsp_cmd);
	}
#endif

	wmb();
	/* update flags */
	xrp_comm_write32(&cmd->flags,
			 (rq->ioctl_queue.flags & ~XRP_DSP_CMD_FLAG_RESPONSE_VALID) |
			 XRP_DSP_CMD_FLAG_REQUEST_VALID);
}

static long xrp_complete_hw_request(struct xrp_dsp_cmd __iomem *cmd,
				    struct xrp_request *rq)
{
	u32 flags = xrp_comm_read32(&cmd->flags);

	if (rq->ioctl_queue.out_data_size <= XRP_DSP_CMD_INLINE_DATA_SIZE)
		xrp_comm_read(&cmd->out_data, rq->out_data,
			      rq->ioctl_queue.out_data_size);
	if (rq->n_buffers <= XRP_DSP_CMD_INLINE_BUFFER_COUNT)
		xrp_comm_read(&cmd->buffer_data, rq->dsp_buffer,
			      rq->n_buffers * sizeof(struct xrp_dsp_buffer));
	return (flags & XRP_DSP_CMD_FLAG_RESPONSE_DELIVERY_FAIL) ? -ENXIO : 0;
}

static long xrp_ioctl_submit_sync(struct file *filp,
				  struct xrp_ioctl_queue __user *p)
{
	struct xvp_file *xvp_file = filp->private_data;
	struct xvp *xvp = xvp_file->xvp;
	struct xrp_request xrp_rq, *rq = &xrp_rq;
	long ret = 0;
	bool went_off = false;

	if (copy_from_user(&rq->ioctl_queue, p, sizeof(*p)))
		return -EFAULT;

	if (rq->ioctl_queue.flags & ~XRP_QUEUE_VALID_FLAGS) {
		dev_dbg(xvp->dev, "%s: invalid flags 0x%08x\n",
			__func__, rq->ioctl_queue.flags);
		return -EINVAL;
	}

	ret = xrp_map_request(filp, rq, current->mm);
	if (ret < 0)
		return ret;

	if (loopback < LOOPBACK_NOIO) {
		mutex_lock(&xvp->comm_lock);

		if (xvp->off) {
			ret = -ENODEV;
		} else {
			xrp_fill_hw_request(xvp->comm, rq, &xvp->address_map);

			xrp_send_device_irq(xvp);

			if (xvp->host_irq_mode) {
				ret = xvp_complete_cmd_irq(xvp,
							   &xvp->completion,
							   xrp_cmd_complete);
			} else {
				ret = xvp_complete_cmd_poll(xvp,
							    xrp_cmd_complete);
			}
#ifdef DEBUG
			xrp_panic_check(xvp);
#endif

			/* copy back inline data */
			if (ret == 0) {
				ret = xrp_complete_hw_request(xvp->comm, rq);
			} else if (ret == -EBUSY && firmware_reboot) {
				int rc;

				dev_dbg(xvp->dev,
					"%s: restarting firmware...\n",
					 __func__);
				rc = xrp_boot_firmware(xvp);
				if (rc < 0) {
					ret = rc;
					went_off = xvp->off;
				}
			}
		}
		mutex_unlock(&xvp->comm_lock);
	}

	if (ret == 0)
		ret = xrp_unmap_request(filp, rq);
	else if (!went_off)
		xrp_unmap_request_nowb(filp, rq);
	/*
	 * Otherwise (if the DSP went off) all mapped buffers are leaked here.
	 * There seems to be no way to recover them as we don't know what's
	 * going on with the DSP; the DSP may still be reading and writing
	 * this memory.
	 */

	return ret;
}

static long xvp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long retval;

	pr_debug("%s: %x\n", __func__, cmd);

	switch(cmd){
	case XRP_IOCTL_ALLOC:
		retval = xrp_ioctl_alloc(filp,
					 (struct xrp_ioctl_alloc __user *)arg);
		break;

	case XRP_IOCTL_FREE:
		retval = xrp_ioctl_free(filp,
					(struct xrp_ioctl_alloc __user *)arg);
		break;

	case XRP_IOCTL_QUEUE:
	case XRP_IOCTL_QUEUE_NS:
		retval = xrp_ioctl_submit_sync(filp,
					       (struct xrp_ioctl_queue __user *)arg);
		break;

	default:
		retval = -EINVAL;
		break;
	}
	return retval;
}

static void xvp_vm_open(struct vm_area_struct *vma)
{
	pr_debug("%s\n", __func__);
	xrp_allocation_get(vma->vm_private_data);
}

static void xvp_vm_close(struct vm_area_struct *vma)
{
	pr_debug("%s\n", __func__);
	xrp_allocation_put(vma->vm_private_data);
}

static const struct vm_operations_struct xvp_vm_ops = {
	.open = xvp_vm_open,
	.close = xvp_vm_close,
};

static int xvp_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int err;
	struct xvp_file *xvp_file = filp->private_data;
	unsigned long pfn = vma->vm_pgoff + PFN_DOWN(xvp_file->xvp->pmem);
	struct xrp_allocation *xrp_allocation;

	pr_debug("%s\n", __func__);
	xrp_allocation = xrp_allocation_dequeue(filp->private_data,
						pfn << PAGE_SHIFT,
						vma->vm_end - vma->vm_start);
	if (xrp_allocation) {
		struct xvp *xvp = xvp_file->xvp;
		pgprot_t prot = vma->vm_page_prot;

		if (!xrp_cacheable(xvp, pfn,
				   PFN_DOWN(vma->vm_end - vma->vm_start))) {
			prot = pgprot_writecombine(prot);
			vma->vm_page_prot = prot;
		}

		err = remap_pfn_range(vma, vma->vm_start, pfn,
				      vma->vm_end - vma->vm_start,
				      prot);

		vma->vm_private_data = xrp_allocation;
		vma->vm_ops = &xvp_vm_ops;
	} else {
		err = -EINVAL;
	}

	return err;
}

static int xvp_open(struct inode *inode, struct file *filp)
{
	struct xvp *xvp = container_of(filp->private_data,
				       struct xvp, miscdev);
	struct xvp_file *xvp_file;
	int rc;

	pr_debug("%s\n", __func__);
	rc = pm_runtime_get_sync(xvp->dev);
	if (rc < 0)
		return rc;

	xvp_file = devm_kzalloc(xvp->dev, sizeof(*xvp_file), GFP_KERNEL);
	if (!xvp_file) {
		pm_runtime_put_sync(xvp->dev);
		return -ENOMEM;
	}

	xvp_file->xvp = xvp;
	spin_lock_init(&xvp_file->busy_list_lock);
	filp->private_data = xvp_file;
	xrp_add_known_file(filp);
	return 0;
}

static int xvp_close(struct inode *inode, struct file *filp)
{
	struct xvp_file *xvp_file = filp->private_data;

	pr_debug("%s\n", __func__);

	xrp_remove_known_file(filp);
	pm_runtime_put_sync(xvp_file->xvp->dev);
	devm_kfree(xvp_file->xvp->dev, xvp_file);
	return 0;
}

static inline int xvp_enable_dsp(struct xvp *xvp)
{
	if (loopback < LOOPBACK_NOMMIO &&
	    xvp->hw_ops->enable)
		return xvp->hw_ops->enable(xvp->hw_arg);
	else
		return 0;
}

static inline void xvp_disable_dsp(struct xvp *xvp)
{
	if (loopback < LOOPBACK_NOMMIO &&
	    xvp->hw_ops->disable)
		xvp->hw_ops->disable(xvp->hw_arg);
}

static inline void xrp_reset_dsp(struct xvp *xvp)
{
	if (loopback < LOOPBACK_NOMMIO &&
	    xvp->hw_ops->reset)
		xvp->hw_ops->reset(xvp->hw_arg);
}

static inline void xrp_halt_dsp(struct xvp *xvp)
{
	if (loopback < LOOPBACK_NOMMIO &&
	    xvp->hw_ops->halt)
		xvp->hw_ops->halt(xvp->hw_arg);
}

static inline void xrp_release_dsp(struct xvp *xvp)
{
	if (loopback < LOOPBACK_NOMMIO &&
	    xvp->hw_ops->release)
		xvp->hw_ops->release(xvp->hw_arg);
}

static int xrp_boot_firmware(struct xvp *xvp)
{
	int ret;
	struct xrp_dsp_sync __iomem *shared_sync = xvp->comm;

	xrp_halt_dsp(xvp);
	xrp_reset_dsp(xvp);

	if (xvp->firmware_name) {
		if (loopback < LOOPBACK_NOFIRMWARE) {
			ret = xrp_request_firmware(xvp);
			if (ret < 0)
				return ret;
		}

		if (loopback < LOOPBACK_NOIO) {
			xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_IDLE);
			mb();
		}
	}
	xrp_release_dsp(xvp);

	if (loopback < LOOPBACK_NOIO) {
		ret = xrp_synchronize(xvp);
		if (ret < 0) {
			xrp_halt_dsp(xvp);
			dev_err(xvp->dev,
				"%s: couldn't synchronize with the DSP core\n",
				__func__);
			dev_err(xvp->dev,
				"XRP device will not use the DSP until the driver is rebound to this device\n");
			xvp->off = true;
			return ret;
		}
	}
	return 0;
}

static const struct file_operations xvp_fops = {
	.owner  = THIS_MODULE,
	.llseek = no_llseek,
	.unlocked_ioctl = xvp_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = xvp_ioctl,
#endif
	.mmap = xvp_mmap,
	.open = xvp_open,
	.release = xvp_close,
};

int xrp_runtime_suspend(struct device *dev)
{
	struct xvp *xvp = dev_get_drvdata(dev);

	xrp_halt_dsp(xvp);
	xvp_disable_dsp(xvp);
	return 0;
}
EXPORT_SYMBOL(xrp_runtime_suspend);

int xrp_runtime_resume(struct device *dev)
{
	struct xvp *xvp = dev_get_drvdata(dev);
	int ret = 0;

	mutex_lock(&xvp->comm_lock);
	if (xvp->off)
		goto out;
	ret = xvp_enable_dsp(xvp);
	if (ret < 0) {
		dev_err(xvp->dev, "couldn't enable DSP\n");
		goto out;
	}

	ret = xrp_boot_firmware(xvp);
	if (ret < 0)
		xvp_disable_dsp(xvp);

out:
	mutex_unlock(&xvp->comm_lock);

	return ret;
}
EXPORT_SYMBOL(xrp_runtime_resume);

static int xrp_init_regs_v0(struct platform_device *pdev, struct xvp *xvp)
{
	struct resource *mem;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!mem)
		return -ENODEV;

	xvp->comm_phys = mem->start;
	xvp->comm = devm_ioremap_resource(&pdev->dev, mem);

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	if (!mem)
		return -ENODEV;

	xvp->pmem = mem->start;
	xvp->shared_size = resource_size(mem);
	return xrp_init_private_pool(&xvp->pool, xvp->pmem,
				     xvp->shared_size);
}

static int xrp_init_regs_v1(struct platform_device *pdev, struct xvp *xvp)
{
	struct resource *mem;
	struct resource r;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem)
		return -ENODEV;

	if (resource_size(mem) < 2 * PAGE_SIZE) {
		dev_err(xvp->dev,
			"%s: shared memory size is too small\n",
			__func__);
		return -ENOMEM;
	}

	xvp->comm_phys = mem->start;
	xvp->pmem = mem->start + PAGE_SIZE;
	xvp->shared_size = resource_size(mem) - PAGE_SIZE;

	r = *mem;
	r.end = r.start + PAGE_SIZE;
	xvp->comm = devm_ioremap_resource(&pdev->dev, &r);
	return xrp_init_private_pool(&xvp->pool, xvp->pmem,
				     xvp->shared_size);
}

static int xrp_init_regs_cma(struct platform_device *pdev, struct xvp *xvp)
{
	dma_addr_t comm_phys;

	if (of_reserved_mem_device_init(xvp->dev) < 0)
		return -ENODEV;

	xvp->comm = dma_alloc_attrs(xvp->dev, PAGE_SIZE, &comm_phys,
				    GFP_KERNEL, 0);
	if (!xvp->comm)
		return -ENOMEM;

	xvp->comm_phys = dma_to_phys(xvp->dev, comm_phys);
	return xrp_init_cma_pool(&xvp->pool, xvp->dev);
}

static long xrp_init_common(struct platform_device *pdev,
			    enum xrp_init_flags init_flags,
			    const struct xrp_hw_ops *hw_ops, void *hw_arg,
			    int (*xrp_init_regs)(struct platform_device *pdev,
						 struct xvp *xvp))
{
	long ret;
	char nodename[sizeof("xvp") + 3 * sizeof(int)];
	struct xvp *xvp;
	int nodeid;

	xvp = devm_kzalloc(&pdev->dev, sizeof(*xvp), GFP_KERNEL);
	if (!xvp) {
		ret = -ENOMEM;
		goto err;
	}

	xvp->dev = &pdev->dev;
	xvp->hw_ops = hw_ops;
	xvp->hw_arg = hw_arg;
	if (init_flags & XRP_INIT_USE_HOST_IRQ)
		xvp->host_irq_mode = true;
	platform_set_drvdata(pdev, xvp);
	mutex_init(&xvp->comm_lock);
	init_completion(&xvp->completion);

	ret = xrp_init_regs(pdev, xvp);
	if (ret < 0)
		goto err;

	pr_debug("%s: comm = %pap/%p\n", __func__, &xvp->comm_phys, xvp->comm);
	pr_debug("%s: xvp->pmem = %pap\n", __func__, &xvp->pmem);

	ret = xrp_init_address_map(xvp->dev, &xvp->address_map);
	if (ret < 0)
		goto err_free_pool;

	ret = device_property_read_string(xvp->dev, "firmware-name",
					  &xvp->firmware_name);
	if (ret == -EINVAL || ret == -ENODATA) {
		dev_dbg(xvp->dev,
			"no firmware-name property, not loading firmware");
	} else if (ret < 0) {
		dev_err(xvp->dev, "invalid firmware name (%ld)", ret);
		goto err_free_map;
	}

	pm_runtime_enable(xvp->dev);
	if (!pm_runtime_enabled(xvp->dev)) {
		ret = xrp_runtime_resume(xvp->dev);
		if (ret)
			goto err_pm_disable;
	}

	nodeid = ida_simple_get(&xvp_nodeid, 0, 0, GFP_KERNEL);
	if (nodeid < 0) {
		ret = nodeid;
		goto err_pm_disable;
	}
	xvp->nodeid = nodeid;
	sprintf(nodename, "xvp%u", nodeid);

	xvp->miscdev = (struct miscdevice){
		.minor = MISC_DYNAMIC_MINOR,
		.name = devm_kstrdup(&pdev->dev, nodename, GFP_KERNEL),
		.nodename = devm_kstrdup(&pdev->dev, nodename, GFP_KERNEL),
		.fops = &xvp_fops,
	};

	ret = misc_register(&xvp->miscdev);
	if (ret < 0)
		goto err_free_id;
	return PTR_ERR(xvp);
err_free_id:
	ida_simple_remove(&xvp_nodeid, nodeid);
err_pm_disable:
	pm_runtime_disable(xvp->dev);
err_free_map:
	xrp_free_address_map(&xvp->address_map);
err_free_pool:
	xrp_free_pool(xvp->pool);
	if (xvp->comm_phys && !xvp->pmem) {
		dma_free_attrs(xvp->dev, PAGE_SIZE, xvp->comm,
			       phys_to_dma(xvp->dev, xvp->comm_phys), 0);
	}
err:
	dev_err(&pdev->dev, "%s: ret = %ld\n", __func__, ret);
	return ret;
}

typedef long xrp_init_function(struct platform_device *pdev,
			       enum xrp_init_flags flags,
			       const struct xrp_hw_ops *hw_ops, void *hw_arg);

xrp_init_function xrp_init;
long xrp_init(struct platform_device *pdev, enum xrp_init_flags flags,
	      const struct xrp_hw_ops *hw_ops, void *hw_arg)
{
	return xrp_init_common(pdev, flags, hw_ops, hw_arg, xrp_init_regs_v0);
}
EXPORT_SYMBOL(xrp_init);

xrp_init_function xrp_init_v1;
long xrp_init_v1(struct platform_device *pdev, enum xrp_init_flags flags,
		 const struct xrp_hw_ops *hw_ops, void *hw_arg)
{
	return xrp_init_common(pdev, flags, hw_ops, hw_arg, xrp_init_regs_v1);
}
EXPORT_SYMBOL(xrp_init_v1);

xrp_init_function xrp_init_cma;
long xrp_init_cma(struct platform_device *pdev, enum xrp_init_flags flags,
		  const struct xrp_hw_ops *hw_ops, void *hw_arg)
{
	return xrp_init_common(pdev, flags, hw_ops, hw_arg, xrp_init_regs_cma);
}
EXPORT_SYMBOL(xrp_init_cma);

int xrp_deinit(struct platform_device *pdev)
{
	struct xvp *xvp = platform_get_drvdata(pdev);

	pm_runtime_disable(xvp->dev);
	if (!pm_runtime_status_suspended(xvp->dev))
		xrp_runtime_suspend(xvp->dev);

	misc_deregister(&xvp->miscdev);
	release_firmware(xvp->firmware);
	xrp_free_pool(xvp->pool);
	if (xvp->comm_phys && !xvp->pmem) {
		dma_free_attrs(xvp->dev, PAGE_SIZE, xvp->comm,
			       phys_to_dma(xvp->dev, xvp->comm_phys), 0);
	}
	xrp_free_address_map(&xvp->address_map);
	ida_simple_remove(&xvp_nodeid, xvp->nodeid);
	return 0;
}
EXPORT_SYMBOL(xrp_deinit);

int xrp_deinit_hw(struct platform_device *pdev, void **hw_arg)
{
	if (hw_arg) {
		struct xvp *xvp = platform_get_drvdata(pdev);
		*hw_arg = xvp->hw_arg;
	}
	return xrp_deinit(pdev);
}
EXPORT_SYMBOL(xrp_deinit_hw);

static void *get_hw_sync_data(void *hw_arg, size_t *sz)
{
	void *p = kzalloc(64, GFP_KERNEL);

	*sz = 64;
	return p;
}

static const struct xrp_hw_ops hw_ops = {
	.get_hw_sync_data = get_hw_sync_data,
};

#ifdef CONFIG_OF
static const struct of_device_id xrp_of_match[] = {
	{
		.compatible = "cdns,xrp",
		.data = xrp_init,
	}, {
		.compatible = "cdns,xrp,v1",
		.data = xrp_init_v1,
	}, {
		.compatible = "cdns,xrp,cma",
		.data = xrp_init_cma,
	}, {},
};
MODULE_DEVICE_TABLE(of, xrp_of_match);
#endif

#ifdef CONFIG_ACPI
static const struct acpi_device_id xrp_acpi_match[] = {
	{ "CXRP0001", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, xrp_acpi_match);
#endif

static int xrp_probe(struct platform_device *pdev)
{
	long ret = -EINVAL;

#ifdef CONFIG_OF
	{
		const struct of_device_id *match;
		xrp_init_function *init;

	        match = of_match_device(xrp_of_match, &pdev->dev);
		init = match->data;
		ret = init(pdev, 0, &hw_ops, NULL);
		return IS_ERR_VALUE(ret) ? ret : 0;
	}
#endif
#ifdef CONFIG_ACPI
	ret = xrp_init_v1(pdev, 0, &hw_ops, NULL);
	if (!IS_ERR_VALUE(ret)) {
		struct xrp_address_map_entry *entry;
		struct xvp *xvp = ERR_PTR(ret);

		ret = 0;
		/*
		 * On ACPI system DSP can currently only access
		 * its own shared memory.
		 */
		entry = xrp_get_address_mapping(&xvp->address_map,
						xvp->comm_phys);
		if (entry) {
			entry->src_addr = xvp->comm_phys;
			entry->dst_addr = (u32)xvp->comm_phys;
			entry->size = (u32)xvp->shared_size + PAGE_SIZE;
		} else {
			dev_err(xvp->dev,
				"%s: couldn't find mapping for shared memory\n",
				__func__);
			ret = -EINVAL;
		}
	}
#endif
	return ret;
}

static int xrp_remove(struct platform_device *pdev)
{
	return xrp_deinit(pdev);
}

static const struct dev_pm_ops xrp_pm_ops = {
	SET_RUNTIME_PM_OPS(xrp_runtime_suspend,
			   xrp_runtime_resume, NULL)
};

static struct platform_driver xrp_driver = {
	.probe   = xrp_probe,
	.remove  = xrp_remove,
	.driver  = {
		.name = DRIVER_NAME,
		.of_match_table = of_match_ptr(xrp_of_match),
		.acpi_match_table = ACPI_PTR(xrp_acpi_match),
		.pm = &xrp_pm_ops,
	},
};

module_platform_driver(xrp_driver);

MODULE_AUTHOR("Takayuki Sugawara");
MODULE_AUTHOR("Max Filippov");
MODULE_DESCRIPTION("XRP: Linux device driver for Xtensa Remote Processing");
MODULE_LICENSE("Dual MIT/GPL");
