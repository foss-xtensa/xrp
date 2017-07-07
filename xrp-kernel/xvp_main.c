/*
 * XRP: Linux device driver for Xtensa Remote Processing
 *
 * Copyright (c) 2015 - 2017 Cadence Design Systems, Inc.
 *
 * License: Dual MIT/GPL.
 */

#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <asm/mman.h>
#include <asm/uaccess.h>
#include "xrp_alloc.h"
#include "xrp_kernel_defs.h"
#include "xrp_kernel_dsp_interface.h"

#define DEFAULT_FIRMWARE_NAME "xvp.elf"
MODULE_FIRMWARE(DEFAULT_FIRMWARE_NAME);

#define XVP_TIMEOUT_JIFFIES (HZ * 10)

#define XVP_REG_RESET		(0x00)
#define XVP_REG_RUNSTALL	(0x04)

#define XRP_REG_RESET		(0x04)
#define XRP_REG_RUNSTALL	(0x08)

struct xvp;
struct xvp_file;

struct xvp_alien_mapping {
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
		XRP_MAPPING_KERNEL,
	} type;
	union {
		struct xrp_allocation *xrp_allocation;
		struct xvp_alien_mapping *xvp_alien_mapping;
	};
};

struct xvp_hw_control {
	void (*reset)(struct xvp *xvp);
	void (*halt)(struct xvp *xvp);
	void (*release)(struct xvp *xvp);
};

enum xrp_irq_mode {
	XRP_IRQ_NONE,
	XRP_IRQ_LEVEL,
	XRP_IRQ_EDGE,
	XRP_IRQ_MAX,
};

struct xvp {
	struct device *dev;
	const char *firmware_name;
	const struct firmware *firmware;
	struct miscdevice miscdev;
	const struct xvp_hw_control *hw_control;

	void __iomem *regs;
	void __iomem *comm;
	phys_addr_t pmem;
	phys_addr_t regs_phys;
	phys_addr_t comm_phys;

	/* how IRQ is used to notify the device of incoming data */
	enum xrp_irq_mode device_irq_mode;
	/*
	 * offset of IRQ register in MMIO region (host side)
	 * bit number
	 * device IRQ#
	 */
	u32 device_irq[3];
	/* how IRQ is used to notify the host of incoming data */
	enum xrp_irq_mode host_irq_mode;
	/*
	 * offset of IRQ register (device side)
	 * bit number
	 */
	u32 host_irq[2];
	struct completion completion;

	struct xrp_allocation_pool pool;
	struct mutex comm_lock;
};

struct xvp_file {
	struct xvp *xvp;
	spinlock_t busy_list_lock;
	struct xrp_allocation *busy_list;
};

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

static unsigned xvp_nodeid;

#define DRIVER_NAME "xrp"

static int xvp_boot_firmware(struct xvp *xvp);

static inline void xvp_reg_write32(struct xvp *xvp, unsigned addr, u32 v)
{
	__raw_writel(v, xvp->regs + addr);
}

static inline u32 xvp_reg_read32(struct xvp *xvp, unsigned addr)
{
	return __raw_readl(xvp->regs + addr);
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
	switch (xvp->device_irq_mode) {
	case XRP_IRQ_EDGE:
		xvp_reg_write32(xvp, xvp->device_irq[0], 0);
		/* fallthrough */
	case XRP_IRQ_LEVEL:
		wmb();
		xvp_reg_write32(xvp, xvp->device_irq[0],
				BIT(xvp->device_irq[1]));
		break;
	default:
		break;
	}
}

static int xvp_synchronize(struct xvp *xvp)
{
	static const int irq_mode[] = {
		[XRP_IRQ_NONE] = XRP_DSP_SYNC_IRQ_MODE_NONE,
		[XRP_IRQ_LEVEL] = XRP_DSP_SYNC_IRQ_MODE_LEVEL,
		[XRP_IRQ_EDGE] = XRP_DSP_SYNC_IRQ_MODE_EDGE,
	};
	unsigned long deadline = jiffies + XVP_TIMEOUT_JIFFIES;
	struct xrp_dsp_sync __iomem *shared_sync = xvp->comm;
	int ret = -ENODEV;
	u32 v;

	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_START);
	mb();
	do {
		v = xrp_comm_read32(&shared_sync->sync);
		if (v == XRP_DSP_SYNC_DSP_READY)
			break;
		schedule();
	} while (time_before(jiffies, deadline));

	if (v != XRP_DSP_SYNC_DSP_READY) {
		dev_err(xvp->dev, "DSP is not ready for synchronization\n");
		goto err;
	}

	xrp_comm_write32(&shared_sync->device_mmio_base,
			 xvp->regs_phys);
	xrp_comm_write32(&shared_sync->host_irq_mode,
			 irq_mode[xvp->host_irq_mode]);
	xrp_comm_write32(&shared_sync->host_irq_offset,
			 xvp->host_irq[0]);
	xrp_comm_write32(&shared_sync->host_irq_bit,
			 xvp->host_irq[1]);
	xrp_comm_write32(&shared_sync->device_irq_mode,
			 irq_mode[xvp->device_irq_mode]);
	xrp_comm_write32(&shared_sync->device_irq_offset,
			 xvp->device_irq[0]);
	xrp_comm_write32(&shared_sync->device_irq_bit,
			 xvp->device_irq[1]);
	xrp_comm_write32(&shared_sync->device_irq,
			 xvp->device_irq[2]);
	mb();
	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_HOST_TO_DSP);
	mb();

	do {
		v = xrp_comm_read32(&shared_sync->sync);
		if (v == XRP_DSP_SYNC_DSP_TO_HOST)
			break;
		schedule();
	} while (time_before(jiffies, deadline));

	if (v != XRP_DSP_SYNC_DSP_TO_HOST) {
		dev_err(xvp->dev,
			"DSP haven't confirmed initialization data reception\n");
		goto err;
	}

	xrp_send_device_irq(xvp);

	if (xvp->host_irq_mode != XRP_IRQ_NONE) {
		int res = wait_for_completion_timeout(&xvp->completion,
						      XVP_TIMEOUT_JIFFIES);
		if (res == 0) {
			dev_err(xvp->dev,
				"host IRQ mode is requested, but DSP couldn't deliver IRQ during synchronization\n");
			goto err;
		}
	}
	ret = 0;
err:
	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_IDLE);
	return ret;
}

static bool xrp_cmd_complete(void *p)
{
	struct xvp *xvp = p;
	struct xrp_dsp_cmd __iomem *cmd = xvp->comm;
	u32 flags = xrp_comm_read32(&cmd->flags);

	rmb();
	return (flags & (XRP_DSP_CMD_FLAG_REQUEST_VALID |
			 XRP_DSP_CMD_FLAG_RESPONSE_VALID)) ==
		(XRP_DSP_CMD_FLAG_REQUEST_VALID |
		 XRP_DSP_CMD_FLAG_RESPONSE_VALID);
}

static irqreturn_t xvp_irq_handler(int irq, void *dev_id)
{
	struct xvp *xvp = dev_id;

	if (!xrp_cmd_complete(xvp))
		return IRQ_NONE;

	if (xvp->host_irq_mode == XRP_IRQ_LEVEL)
		xvp_reg_write32(xvp, xvp->host_irq[0], 0);

	complete(&xvp->completion);

	return IRQ_HANDLED;
}

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

	err = xrp_allocate(&xvp_file->xvp->pool,
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

#if defined(__XTENSA__)
static inline void xvp_clean_cache(void *vaddr, phys_addr_t paddr,
				   unsigned long sz)
{
	__flush_dcache_range((unsigned long)vaddr, sz);
}
static inline void xvp_flush_cache(void *vaddr, phys_addr_t paddr,
				   unsigned long sz)
{
	__flush_dcache_range((unsigned long)vaddr, sz);
	__invalidate_dcache_range((unsigned long)vaddr, sz);
}
static inline void xvp_invalidate_cache(void *vaddr, phys_addr_t paddr,
				 unsigned long sz)
{
	__invalidate_dcache_range((unsigned long)vaddr, sz);
}
#elif defined(__arm__)
static inline void xvp_clean_cache(void *vaddr, phys_addr_t paddr,
				   unsigned long sz)
{
	__cpuc_flush_dcache_area(vaddr, sz);
	outer_clean_range(paddr, paddr + sz);
}
static inline void xvp_flush_cache(void *vaddr, phys_addr_t paddr,
				   unsigned long sz)
{
	__cpuc_flush_dcache_area(vaddr, sz);
	outer_flush_range(paddr, paddr + sz);
}
static inline void xvp_invalidate_cache(void *vaddr, phys_addr_t paddr,
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
		xrp_allocation_put(alien_mapping->allocation);
		break;
	default:
		break;
	}
	kfree(alien_mapping);
}

static long xvp_pfn_virt_to_phys(struct xvp_file *xvp_file,
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

static long _xrp_copy_user_phys(struct xvp *xvp,
				unsigned long vaddr, unsigned long size,
				phys_addr_t paddr, bool to_phys)
{
	if (pfn_valid(__phys_to_pfn(paddr))) {
		struct page *page = pfn_to_page(__phys_to_pfn(paddr));
		size_t page_offs = paddr & ~PAGE_MASK;
		size_t offs;

		if (!to_phys)
			dma_sync_single_for_cpu(xvp->dev, paddr, size,
						DMA_FROM_DEVICE);
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
			dma_sync_single_for_device(xvp->dev, paddr, size,
						   DMA_TO_DEVICE);
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
				  phys_addr_t paddr)
{
	return _xrp_copy_user_phys(xvp, vaddr, size, paddr, true);
}

static long xrp_copy_user_from_phys(struct xvp *xvp,
				    unsigned long vaddr, unsigned long size,
				    phys_addr_t paddr)
{
	return _xrp_copy_user_phys(xvp, vaddr, size, paddr, false);
}

static long xvp_copy_virt_to_phys(struct xvp_file *xvp_file,
				  unsigned long flags,
				  unsigned long vaddr, unsigned long size,
				  unsigned long *paddr,
				  struct xvp_alien_mapping **mapping)
{
	unsigned long phys;
	unsigned long align = clamp(vaddr & -vaddr, PAGE_SIZE, 16ul);
	unsigned long offset = vaddr & (align - 1);
	struct xrp_allocation *allocation;
	struct xvp_alien_mapping *alien_mapping;
	long rc;

	rc = xrp_allocate(&xvp_file->xvp->pool,
			  size + align, align, &allocation);
	if (rc < 0)
		return rc;

	phys = (allocation->start & -align) | offset;
	if (phys < allocation->start)
		phys += align;

	if (flags & XRP_FLAG_READ) {
		if (xrp_copy_user_to_phys(xvp_file->xvp,
					  vaddr, size, phys)) {
			xrp_allocation_put(allocation);
			return -EFAULT;
		}
	}

	*paddr = phys;
	alien_mapping = xvp_alien_mapping_create((struct xvp_alien_mapping){
						 .vaddr = vaddr,
						 .size = size,
						 .paddr = *paddr,
						 .allocation = allocation,
						 .type = ALIEN_COPY,
						 });
	if (!alien_mapping) {
		xrp_allocation_put(allocation);
		return -ENOMEM;
	}

	*mapping = alien_mapping;
	pr_debug("%s: copying to pa: 0x%08lx\n", __func__, phys);

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
			     unsigned long flags, unsigned long *paddr,
			     struct xrp_mapping *mapping)
{
	unsigned long phys = __pa(virt);

	mapping->type = XRP_MAPPING_KERNEL;
	*paddr = phys;
	pr_debug("%s: sharing kernel-only buffer: 0x%08lx\n", __func__, phys);
	pr_debug("%s: mapping = %p, mapping->type = %d\n",
		 __func__, mapping, mapping->type);

	if (flags & XRP_FLAG_WRITE) {
		xvp_flush_cache((void *)virt, phys, size);
	} else if (flags & XRP_FLAG_READ) {
		xvp_clean_cache((void *)virt, phys, size);
	}
	return 0;
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
			      unsigned long flags, unsigned long *paddr,
			      struct xrp_mapping *mapping)
{
	unsigned long phys = ~0ul;
	struct xvp_file *xvp_file = filp->private_data;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma = find_vma(mm, virt);
	bool do_cache = true;

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
		struct xrp_allocation *xrp_allocation =
			vma->vm_private_data;

		mapping->type = XRP_MAPPING_NATIVE;
		mapping->xrp_allocation = xrp_allocation;
		xrp_allocation_get(mapping->xrp_allocation);
		phys = xvp_file->xvp->pmem + (vma->vm_pgoff << PAGE_SHIFT) +
			virt - vma->vm_start;
	} else {
		struct xvp_alien_mapping *alien_mapping = NULL;
		long rc;

		/* Otherwise this is alien allocation. */
		pr_debug("%s: non-XVP allocation at 0x%08lx\n",
			 __func__, virt);

		if (vma && vma->vm_flags & (VM_IO | VM_PFNMAP)) {
			rc = xvp_pfn_virt_to_phys(xvp_file, vma,
						  virt, size,
						  &phys,
						  &alien_mapping);
		} else {
			up_read(&mm->mmap_sem);
			rc = xvp_gup_virt_to_phys(xvp_file, virt,
						  size, &phys,
						  &alien_mapping);
			down_read(&mm->mmap_sem);
		}

		/*
		 * If we couldn't share try to make a shadow copy.
		 */
		if (rc < 0) {
			rc = xvp_copy_virt_to_phys(xvp_file, flags,
						   virt, size, &phys,
						   &alien_mapping);
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
		mapping->xvp_alien_mapping = alien_mapping;
	}

	*paddr = phys;
	pr_debug("%s: mapping = %p, mapping->type = %d\n",
		 __func__, mapping, mapping->type);

	if (do_cache) {
		if (flags & XRP_FLAG_WRITE) {
			xvp_flush_cache((void *)virt, phys, size);
		} else if (flags & XRP_FLAG_READ) {
			xvp_clean_cache((void *)virt, phys, size);
		}
	}
	return 0;
}

static long xrp_writeback_alien_mapping(struct xvp_file *xvp_file,
					struct xvp_alien_mapping *alien_mapping)
{
	struct page *page;
	size_t nr_pages;
	size_t i;
	long ret = 0;

	switch (alien_mapping->type) {
	case ALIEN_GUP:
		pr_debug("%s: dirtying alien GUP @va = %p, pa = %pap\n",
			 __func__, (void __user *)alien_mapping->vaddr,
			 &alien_mapping->paddr);
		page = pfn_to_page(__phys_to_pfn(alien_mapping->paddr));
		nr_pages =
			((alien_mapping->vaddr + alien_mapping->size +
			  PAGE_SIZE - 1) >> PAGE_SHIFT) -
			(alien_mapping->vaddr >> PAGE_SHIFT);
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
					    alien_mapping->paddr))
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

	switch (mapping->type) {
	case XRP_MAPPING_NATIVE:
		xrp_allocation_put(mapping->xrp_allocation);
		break;

	case XRP_MAPPING_ALIEN:
		if (flags & XRP_FLAG_WRITE)
			ret = xrp_writeback_alien_mapping(filp->private_data,
							  mapping->xvp_alien_mapping);

		xvp_alien_mapping_destroy(mapping->xvp_alien_mapping);
		break;

	case XRP_MAPPING_KERNEL:
		break;

	default:
		break;
	}

	mapping->type = XRP_MAPPING_NONE;

	return ret;
}

static bool xrp_unshare_block_need_mm(struct xrp_mapping *mapping,
				      unsigned long flags)
{
	return mapping->type == XRP_MAPPING_ALIEN &&
		(flags & XRP_FLAG_WRITE) &&
		mapping->xvp_alien_mapping->type == ALIEN_COPY;
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

static long xvp_complete_cmd_irq(struct completion *completion,
				 bool (*cmd_complete)(void *p),
				 void *p)
{
	long timeout = XVP_TIMEOUT_JIFFIES;

	do {
		timeout = wait_for_completion_interruptible_timeout(completion,
								    timeout);
		if (cmd_complete(p))
			return 0;
	} while (timeout > 0);

	if (timeout == 0)
		return -EBUSY;
	return timeout;
}

static long xvp_complete_cmd_poll(bool (*cmd_complete)(void *p),
				  void *p)
{
	unsigned long deadline = jiffies + XVP_TIMEOUT_JIFFIES;

	do {
		if (cmd_complete(p))
			return 0;
		schedule();
	} while (time_before(jiffies, deadline));

	return -EBUSY;
}

struct xrp_request {
	struct xrp_ioctl_queue ioctl_queue;
	size_t n_buffers;
	struct xrp_mapping *buffer_mapping;
	struct xrp_dsp_buffer *dsp_buffer;
	unsigned long in_data_phys;
	unsigned long out_data_phys;
	unsigned long dsp_buffer_phys;
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

static long xrp_unmap_request(struct file *filp, struct xrp_request *rq,
			      bool has_mm, bool *_need_mm)
{
	bool need_mm = false;
	bool need_mm_buffers = false;
	size_t n_buffers = rq->n_buffers;
	size_t i;
	long ret = 0;
	long rc;

	if (rq->ioctl_queue.in_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE)
		__xrp_unshare_block(filp, &rq->in_data_mapping, XRP_FLAG_READ);
	if (rq->ioctl_queue.out_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		if (!has_mm && xrp_unshare_block_need_mm(&rq->out_data_mapping,
							 XRP_FLAG_WRITE)) {
			need_mm = true;
		} else {
			rc = __xrp_unshare_block(filp, &rq->out_data_mapping,
						 XRP_FLAG_WRITE);

			if (rc < 0) {
				pr_debug("%s: out_data could not be unshared\n",
					 __func__);
				ret = rc;
			}
		}
	} else if (has_mm) {
		if (copy_to_user((void __user *)(unsigned long)rq->ioctl_queue.out_data_addr,
				 rq->out_data,
				 rq->ioctl_queue.out_data_size)) {
			pr_debug("%s: out_data could not be copied\n",
				 __func__);
			ret = -EFAULT;
		}
	} else {
		need_mm = true;
	}

	if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT)
		__xrp_unshare_block(filp, &rq->dsp_buffer_mapping,
				    XRP_FLAG_READ_WRITE);

	for (i = 0; i < n_buffers; ++i) {
		if (!has_mm &&
		    xrp_unshare_block_need_mm(rq->buffer_mapping + i,
					      rq->dsp_buffer[i].flags)) {
			need_mm_buffers = true;
		} else {
			rc = __xrp_unshare_block(filp, rq->buffer_mapping + i,
						 rq->dsp_buffer[i].flags);
			if (rc < 0) {
				pr_debug("%s: buffer %zd could not be unshared\n",
					 __func__, i);
				ret = rc;
			}
		}
	}

	if (!need_mm_buffers && n_buffers) {
		kfree(rq->buffer_mapping);
		if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
			kfree(rq->dsp_buffer);
		}
		rq->n_buffers = 0;
	}

	if (_need_mm)
		*_need_mm = need_mm || need_mm_buffers;
	return ret;
}

static long xrp_map_request(struct file *filp, struct xrp_request *rq,
			    struct mm_struct *mm)
{
	struct xrp_ioctl_buffer __user *buffer;
	size_t n_buffers = rq->ioctl_queue.buffer_size /
		sizeof(struct xrp_ioctl_buffer);

	size_t i;
	long ret = 0;

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
		unsigned long buffer_phys = ~0ul;

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
			.addr = buffer_phys,
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
				struct xrp_request *rq)
{
	xrp_comm_write32(&cmd->in_data_size, rq->ioctl_queue.in_data_size);
	xrp_comm_write32(&cmd->out_data_size, rq->ioctl_queue.out_data_size);
	xrp_comm_write32(&cmd->buffer_size,
			 rq->n_buffers * sizeof(struct xrp_dsp_buffer));

	if (rq->ioctl_queue.in_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE)
		xrp_comm_write32(&cmd->in_data_addr, rq->in_data_phys);
	else
		xrp_comm_write(&cmd->in_data, rq->in_data,
			       rq->ioctl_queue.in_data_size);

	if (rq->ioctl_queue.out_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE)
		xrp_comm_write32(&cmd->out_data_addr, rq->out_data_phys);

	if (rq->n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT)
		xrp_comm_write32(&cmd->buffer_addr, rq->dsp_buffer_phys);
	else
		xrp_comm_write(&cmd->buffer_data, rq->dsp_buffer,
			       rq->n_buffers * sizeof(struct xrp_dsp_buffer));

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

static void xrp_complete_hw_request(struct xrp_dsp_cmd __iomem *cmd,
				    struct xrp_request *rq)
{
	if (rq->ioctl_queue.out_data_size <= XRP_DSP_CMD_INLINE_DATA_SIZE)
		xrp_comm_read(&cmd->out_data, rq->out_data,
			      rq->ioctl_queue.out_data_size);
	if (rq->n_buffers <= XRP_DSP_CMD_INLINE_BUFFER_COUNT)
		xrp_comm_read(&cmd->buffer_data, rq->dsp_buffer,
			      rq->n_buffers * sizeof(struct xrp_dsp_buffer));
}

static long xrp_ioctl_submit_sync(struct file *filp,
				  struct xrp_ioctl_queue __user *p)
{
	struct xvp_file *xvp_file = filp->private_data;
	struct xvp *xvp = xvp_file->xvp;
	struct xrp_request *rq = kzalloc(sizeof(*rq), GFP_KERNEL);
	long ret = 0;

	if (!rq)
		return -ENOMEM;

	if (copy_from_user(&rq->ioctl_queue, p, sizeof(*p)))
		return -EFAULT;

	ret = xrp_map_request(filp, rq, current->mm);
	if (ret < 0) {
		kfree(rq);
		return ret;
	}

	if (loopback < LOOPBACK_NOIO) {
		mutex_lock(&xvp->comm_lock);

		xrp_fill_hw_request(xvp->comm, rq);

		xrp_send_device_irq(xvp);

		if (xvp->host_irq_mode != XRP_IRQ_NONE) {
			ret = xvp_complete_cmd_irq(&xvp->completion,
						   xrp_cmd_complete, xvp);
		} else {
			ret = xvp_complete_cmd_poll(xrp_cmd_complete, xvp);
		}

		/* copy back inline data */
		if (ret == 0) {
			xrp_complete_hw_request(xvp->comm, rq);
		} else if (ret == -EBUSY && firmware_reboot) {
			int rc;

			pr_debug("%s: restarting firmware...\n", __func__);
			rc = xvp_boot_firmware(xvp);
			if (rc < 0)
				ret = rc;
		}
		mutex_unlock(&xvp->comm_lock);
	}

	if (ret == 0)
		ret = xrp_unmap_request(filp, rq, true, NULL);
	else
		xrp_unmap_request_nowb(filp, rq);
	kfree(rq);

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
	unsigned long pfn = vma->vm_pgoff + (xvp_file->xvp->pmem >> PAGE_SHIFT);
	struct xrp_allocation *xrp_allocation;

	pr_debug("%s\n", __func__);
	xrp_allocation = xrp_allocation_dequeue(filp->private_data,
						pfn << PAGE_SHIFT,
						vma->vm_end - vma->vm_start);
	if (xrp_allocation) {
		err = remap_pfn_range(vma, vma->vm_start, pfn,
				      vma->vm_end - vma->vm_start,
				      vma->vm_page_prot);


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
	struct xvp_file *xvp_file =
		devm_kzalloc(xvp->dev, sizeof(*xvp_file), GFP_KERNEL);

	pr_debug("%s\n", __func__);
	if (!xvp_file)
		return -ENOMEM;

	xvp_file->xvp = xvp;
	spin_lock_init(&xvp_file->busy_list_lock);
	filp->private_data = xvp_file;
	return 0;
}

static int xvp_close(struct inode *inode, struct file *filp)
{
	struct xvp_file *xvp_file = filp->private_data;

	pr_debug("%s\n", __func__);

	devm_kfree(xvp_file->xvp->dev, xvp_file);
	return 0;
}

static inline void xvp_reset_dsp(struct xvp *xvp)
{
	if (loopback < LOOPBACK_NOMMIO)
		xvp->hw_control->reset(xvp);
}

static inline void xvp_halt_dsp(struct xvp *xvp)
{
	if (loopback < LOOPBACK_NOMMIO)
		xvp->hw_control->halt(xvp);
}

static inline void xvp_release_dsp(struct xvp *xvp)
{
	if (loopback < LOOPBACK_NOMMIO)
		xvp->hw_control->release(xvp);
}

static phys_addr_t xvp_translate_addr(struct xvp *xvp, Elf32_Phdr *phdr)
{
	__be32 addr = cpu_to_be32((u32)phdr->p_paddr);

	return of_translate_address(xvp->dev->of_node, &addr);
}

static int xvp_load_segment_to_sysmem(struct xvp *xvp, Elf32_Phdr *phdr)
{
	phys_addr_t pa = xvp_translate_addr(xvp, phdr);
	struct page *page = pfn_to_page(__phys_to_pfn(pa));
	size_t page_offs = pa & ~PAGE_MASK;
	size_t offs;

	for (offs = 0; offs < phdr->p_memsz; ++page) {
		void *p = kmap(page);
		size_t sz = PAGE_SIZE - page_offs;

		if (!p)
			return -ENOMEM;

		page_offs &= ~PAGE_MASK;

		if (offs < phdr->p_filesz) {
			size_t copy_sz = sz;

			if (phdr->p_filesz - offs < copy_sz)
				copy_sz = phdr->p_filesz - offs;

			copy_sz = ALIGN(copy_sz, 4);
			memcpy(p + page_offs,
			       (void *)xvp->firmware->data +
			       phdr->p_offset + offs,
			       copy_sz);
			page_offs += copy_sz;
			offs += copy_sz;
			sz -= copy_sz;
		}

		if (offs < phdr->p_memsz && sz) {
			if (phdr->p_memsz - offs < sz)
				sz = phdr->p_memsz - offs;

			sz = ALIGN(sz, 4);
			memset(p + page_offs, 0, sz);
			page_offs += sz;
			offs += sz;
		}
		kunmap(page);
	}
	dma_sync_single_for_device(xvp->dev, pa, phdr->p_memsz, DMA_TO_DEVICE);
	return 0;
}

static int xvp_load_segment_to_iomem(struct xvp *xvp, Elf32_Phdr *phdr)
{
	phys_addr_t pa = xvp_translate_addr(xvp, phdr);
	void __iomem *p = ioremap(pa, phdr->p_memsz);

	if (!p) {
		dev_err(xvp->dev,
			"couldn't ioremap %pap x 0x%08x\n",
			&pa, (u32)phdr->p_memsz);
		return -EINVAL;
	}
	memcpy_toio(p, (void *)xvp->firmware->data + phdr->p_offset,
		    ALIGN(phdr->p_filesz, 4));
	memset_io(p + ALIGN(phdr->p_filesz, 4), 0,
		  ALIGN(phdr->p_memsz - ALIGN(phdr->p_filesz, 4), 4));
	iounmap(p);
	return 0;
}

static inline bool xrp_section_bad(struct xvp *xvp, const Elf32_Shdr *shdr)
{
	return shdr->sh_offset > xvp->firmware->size ||
		shdr->sh_size > xvp->firmware->size - shdr->sh_offset;
}

static int xrp_firmware_find_symbol(struct xvp *xvp, const char *name,
				    void **paddr, size_t *psize)
{
	const Elf32_Ehdr *ehdr = (Elf32_Ehdr *)xvp->firmware->data;
	const void *shdr_data = xvp->firmware->data + ehdr->e_shoff;
	const Elf32_Shdr *sh_symtab = NULL;
	const Elf32_Shdr *sh_strtab = NULL;
	const void *sym_data;
	const void *str_data;
	const Elf32_Sym *esym;
	void *addr = NULL;
	unsigned i;

	if (ehdr->e_shoff == 0) {
		dev_dbg(xvp->dev, "%s: no section header in the firmware image",
			__func__);
		return -ENOENT;
	}
	if (ehdr->e_shoff > xvp->firmware->size ||
	    ehdr->e_shnum * ehdr->e_shentsize > xvp->firmware->size - ehdr->e_shoff) {
		dev_err(xvp->dev, "%s: bad firmware SHDR information",
			__func__);
		return -EINVAL;
	}

	/* find symbols and string sections */

	for (i = 0; i < ehdr->e_shnum; ++i) {
		const Elf32_Shdr *shdr = shdr_data + i * ehdr->e_shentsize;

		switch (shdr->sh_type) {
		case SHT_SYMTAB:
			sh_symtab = shdr;
			break;
		case SHT_STRTAB:
			sh_strtab = shdr;
			break;
		default:
			break;
		}
	}

	if (!sh_symtab || !sh_strtab) {
		dev_dbg(xvp->dev, "%s: no symtab or strtab in the firmware image",
			__func__);
		return -ENOENT;
	}

	if (xrp_section_bad(xvp, sh_symtab)) {
		dev_err(xvp->dev, "%s: bad firmware SYMTAB section information",
			__func__);
		return -EINVAL;
	}

	if (xrp_section_bad(xvp, sh_strtab)) {
		dev_err(xvp->dev, "%s: bad firmware STRTAB section information",
			__func__);
		return -EINVAL;
	}

	/* iterate through all symbols, searching for the name */

	sym_data = xvp->firmware->data + sh_symtab->sh_offset;
	str_data = xvp->firmware->data + sh_strtab->sh_offset;

	for (i = 0; i < sh_symtab->sh_size; i += sh_symtab->sh_entsize) {
		esym = sym_data + i;

		if (!(ELF_ST_TYPE(esym->st_info) == STT_OBJECT &&
		      esym->st_name < sh_strtab->sh_size &&
		      strncmp(str_data + esym->st_name, name,
			      sh_strtab->sh_size - esym->st_name) == 0))
			continue;

		if (esym->st_shndx > 0 && esym->st_shndx < ehdr->e_shnum) {
			const Elf32_Shdr *shdr = shdr_data +
				esym->st_shndx * ehdr->e_shentsize;
			Elf32_Off in_section_off = esym->st_value - shdr->sh_addr;

			if (xrp_section_bad(xvp, shdr)) {
				dev_err(xvp->dev, "%s: bad firmware section #%d information",
					__func__, esym->st_shndx);
				return -EINVAL;
			}

			if (esym->st_value < shdr->sh_addr ||
			    in_section_off > shdr->sh_size ||
			    esym->st_size > shdr->sh_size - in_section_off) {
				dev_err(xvp->dev, "%s: bad symbol information",
					__func__);
				return -EINVAL;
			}
			addr = (void *)xvp->firmware->data + shdr->sh_offset +
				in_section_off;

			dev_dbg(xvp->dev, "%s: found symbol, st_shndx = %d, "
				"sh_offset = 0x%08x, sh_addr = 0x%08x, "
				"st_value = 0x%08x, address = %p",
				__func__, esym->st_shndx, shdr->sh_offset,
				shdr->sh_addr, esym->st_value, addr);
		} else {
			dev_dbg(xvp->dev, "%s: unsupported section index in found symbol: 0x%x",
				__func__, esym->st_shndx);
			return -EINVAL;
		}
		break;
	}

	if (!addr)
		return -ENOENT;

	*paddr = addr;
	*psize = esym->st_size;

	return 0;
}

static int xrp_firmware_fixup_symbol(struct xvp *xvp, const char *name,
				     phys_addr_t v)
{
	u32 v32 = XRP_DSP_COMM_BASE_MAGIC;
	void *addr;
	size_t sz;
	int rc;

	rc = xrp_firmware_find_symbol(xvp, name, &addr, &sz);
	if (rc < 0) {
		dev_err(xvp->dev, "%s: symbol \"%s\" is not found",
			__func__, name);
		return rc;
	}

	if (sz != sizeof(u32)) {
		dev_err(xvp->dev, "%s: symbol \"%s\" has wrong size: %zu",
			__func__, name, sz);
		return -EINVAL;
	}

	/* update data associated with symbol */

	if (memcmp(addr, &v32, sz) != 0) {
		dev_dbg(xvp->dev, "%s: value pointed to by symbol is incorrect: %*ph",
			__func__, (int)sz, addr);
	}

	v32 = v;
	memcpy(addr, &v32, sz);

	return 0;
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

	xrp_firmware_fixup_symbol(xvp, "xrp_dsp_comm_base", xvp->comm_phys);

	for (i = 0; i < ehdr->e_phnum; ++i) {
		Elf32_Phdr *phdr = (void *)xvp->firmware->data +
			ehdr->e_phoff + i * ehdr->e_phentsize;
		phys_addr_t pa;
		int rc;

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

		pa = xvp_translate_addr(xvp, phdr);
		if (pa == OF_BAD_ADDR) {
			dev_err(xvp->dev,
				"device address 0x%08x could not be mapped to host physical address",
				(u32)phdr->p_paddr);
			return -EINVAL;
		}
		dev_dbg(xvp->dev, "loading segment %d (device 0x%08x) to physical %pap\n",
			i, (u32)phdr->p_paddr, &pa);

		if (pfn_valid(__phys_to_pfn(pa)))
			rc = xvp_load_segment_to_sysmem(xvp, phdr);
		else
			rc = xvp_load_segment_to_iomem(xvp, phdr);

		if (rc < 0)
			return rc;
	}

	return 0;
}

static int xvp_request_firmware(struct xvp *xvp)
{
	int ret = request_firmware(&xvp->firmware, xvp->firmware_name,
				   xvp->dev);

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
	struct xrp_dsp_sync __iomem *shared_sync = xvp->comm;

	if (loopback < LOOPBACK_NOFIRMWARE) {
		ret = xvp_request_firmware(xvp);
		if (ret < 0)
			return ret;
	}

	if (loopback < LOOPBACK_NOIO) {
		xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_IDLE);
		mb();
	}
	xvp_release_dsp(xvp);

	if (loopback < LOOPBACK_NOIO) {
		ret = xvp_synchronize(xvp);
		if (ret < 0) {
			xvp_halt_dsp(xvp);
			pr_err("%s: couldn't synchronize with IVP core\n",
			       __func__);
			return ret;
		}
	}
	return 0;
}

static const struct file_operations xvp_fops = {
	.owner  = THIS_MODULE,
	.llseek = no_llseek,
	.unlocked_ioctl = xvp_ioctl,
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
	char nodename[sizeof("xvp") + 3 * sizeof(int)];

	xvp = devm_kzalloc(&pdev->dev, sizeof(*xvp), GFP_KERNEL);
	if (!xvp) {
		ret = -ENOMEM;
		goto err;
	}
	xvp->dev = &pdev->dev;
	platform_set_drvdata(pdev, xvp);
	mutex_init(&xvp->comm_lock);

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		ret = -ENODEV;
		goto err;
	}
	xvp->regs_phys = mem->start;
	xvp->regs = devm_ioremap_resource(&pdev->dev, mem);
	pr_debug("%s: regs = %pap/%p\n", __func__, &mem->start, xvp->regs);

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!mem) {
		ret = -ENODEV;
		goto err;
	}
	xvp->comm_phys = mem->start;
	xvp->comm = devm_ioremap_resource(&pdev->dev, mem);
	pr_debug("%s: comm = %pap/%p\n", __func__, &mem->start, xvp->comm);

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	if (!mem) {
		ret = -ENODEV;
		goto err;
	}

	ret = of_property_read_u32_array(pdev->dev.of_node, "device-irq",
					 xvp->device_irq,
					 ARRAY_SIZE(xvp->device_irq));
	if (ret == 0) {
		u32 device_irq_mode;

		ret = of_property_read_u32(pdev->dev.of_node,
					   "device-irq-mode",
					   &device_irq_mode);
		if (device_irq_mode < XRP_IRQ_MAX)
			xvp->device_irq_mode = device_irq_mode;
		else
			ret = -ENOENT;
	}
	if (ret == 0) {
		dev_dbg(xvp->dev,
			"%s: device IRQ MMIO offset = 0x%08x, bit = %d, device IRQ = %d, IRQ mode = %d",
			__func__, xvp->device_irq[0], xvp->device_irq[1],
			xvp->device_irq[2], xvp->device_irq_mode);
	} else {
		dev_info(xvp->dev, "using polling mode on the device side\n");
	}

	ret = of_property_read_u32_array(pdev->dev.of_node, "host-irq",
					 xvp->host_irq,
					 ARRAY_SIZE(xvp->host_irq));
	if (ret == 0) {
		u32 host_irq_mode;

		ret = of_property_read_u32(pdev->dev.of_node,
					   "host-irq-mode",
					   &host_irq_mode);
		if (host_irq_mode < XRP_IRQ_MAX)
			xvp->host_irq_mode = host_irq_mode;
		else
			ret = -ENOENT;
	}
	irq = platform_get_irq(pdev, 0);
	if (ret == 0 && irq >= 0) {
		dev_dbg(xvp->dev, "%s: host IRQ = %d, ", __func__, irq);
		init_completion(&xvp->completion);
		ret = devm_request_irq(&pdev->dev, irq, xvp_irq_handler,
				       IRQF_SHARED, pdev->name, xvp);
		if (ret < 0) {
			dev_err(&pdev->dev, "request_irq %d failed\n", irq);
			goto err;
		}
	} else {
		dev_info(xvp->dev, "using polling mode on the host side\n");
	}

	xvp->pmem = mem->start;
	pr_debug("%s: xvp->pmem = %pap\n", __func__, &xvp->pmem);
	ret = xrp_init_pool(&xvp->pool, mem->start, resource_size(mem));
	if (ret < 0)
		goto err;

	xvp->hw_control = of_device_get_match_data(xvp->dev);
	if (xvp->hw_control == NULL) {
		dev_err(xvp->dev, "couldn't get hw_control for this device");
		ret = -EINVAL;
		goto err_free;
	}
	ret = of_property_read_string(pdev->dev.of_node, "firmware-name",
				      &xvp->firmware_name);
	if (ret == -EINVAL) {
		xvp->firmware_name = DEFAULT_FIRMWARE_NAME;
		dev_dbg(xvp->dev,
			"no firmware-name property, defaulting to \"%s\"",
			xvp->firmware_name);
	} else if (ret < 0) {
		dev_err(xvp->dev, "invalid firmware name (%d)", ret);
		goto err_free;
	}

	xvp_reset_dsp(xvp);

	ret = xvp_boot_firmware(xvp);
	if (ret < 0)
		goto err_free;

	sprintf(nodename, "xvp%u", xvp_nodeid++);

	xvp->miscdev = (struct miscdevice){
		.minor = MISC_DYNAMIC_MINOR,
		.name = devm_kstrdup(&pdev->dev, nodename, GFP_KERNEL),
		.nodename = devm_kstrdup(&pdev->dev, nodename, GFP_KERNEL),
		.fops = &xvp_fops,
	};

	ret = misc_register(&xvp->miscdev);
	if (ret < 0)
		goto err_free;
	return 0;
err_free:
	xrp_free_pool(&xvp->pool);
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
	xrp_free_pool(&xvp->pool);
	--xvp_nodeid;
	return 0;
}

static void xvp_reset_hw(struct xvp *xvp)
{
	xvp_reg_write32(xvp, XVP_REG_RESET, 1);
	udelay(1);
	xvp_reg_write32(xvp, XVP_REG_RESET, 0);
}

static void xvp_halt_hw(struct xvp *xvp)
{
	xvp_reg_write32(xvp, XVP_REG_RUNSTALL, 1);
}

static void xvp_release_hw(struct xvp *xvp)
{
	xvp_reg_write32(xvp, XVP_REG_RUNSTALL, 0);
}

static void xrp_reset_hw(struct xvp *xvp)
{
	xvp_reg_write32(xvp, XRP_REG_RESET, 1);
	udelay(1);
	xvp_reg_write32(xvp, XRP_REG_RESET, 0);
}

static void xrp_halt_hw(struct xvp *xvp)
{
	xvp_reg_write32(xvp, XRP_REG_RUNSTALL, 1);
}

static void xrp_release_hw(struct xvp *xvp)
{
	xvp_reg_write32(xvp, XRP_REG_RUNSTALL, 0);
}

#ifdef CONFIG_OF
static const struct of_device_id xvp_match[] = {
	{
		.compatible = "cdns,xvp",
		.data = &(struct xvp_hw_control){
			.reset = xvp_reset_hw,
			.halt = xvp_halt_hw,
			.release = xvp_release_hw,
		},
	}, {
		.compatible = "cdns,xrp",
		.data = &(struct xvp_hw_control){
			.reset = xrp_reset_hw,
			.halt = xrp_halt_hw,
			.release = xrp_release_hw,
		},
	}, {},
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
MODULE_DESCRIPTION("XRP: Linux device driver for Xtensa Remote Processing");
MODULE_LICENSE("Dual MIT/GPL");
