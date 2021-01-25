/*
 * xrp_hw_simple: Simple xtensa/arm low-level XRP driver
 *
 * Copyright (c) 2017 Cadence Design Systems, Inc.
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

#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include "xrp_kernel_defs.h"
#include "xrp_hw.h"
#include "xrp_hw_simple_dsp_interface.h"

#define DRIVER_NAME "xrp-hw-simple"

#define XRP_REG_RESET		(0x04)
#define XRP_REG_RUNSTALL	(0x08)

enum xrp_irq_mode {
	XRP_IRQ_NONE,
	XRP_IRQ_LEVEL,
	XRP_IRQ_EDGE,
	XRP_IRQ_EDGE_SW,
	XRP_IRQ_MAX,
};

struct xrp_hw_simple {
	struct xvp *xrp;
	phys_addr_t regs_phys;
	void __iomem *regs;

	/* how IRQ is used to notify the device of incoming data */
	enum xrp_irq_mode device_irq_mode;
	/*
	 * offset of device IRQ register in MMIO region (device side)
	 * bit number
	 * device IRQ#
	 */
	u32 device_irq[3];
	/* offset of devuce IRQ register in MMIO region (host side) */
	u32 device_irq_host_offset;
	/* how IRQ is used to notify the host of incoming data */
	enum xrp_irq_mode host_irq_mode;
	/*
	 * offset of IRQ register (device side)
	 * bit number
	 */
	u32 host_irq[2];
};

static inline void reg_write32(struct xrp_hw_simple *hw, unsigned addr, u32 v)
{
	if (hw->regs)
		__raw_writel(v, hw->regs + addr);
}

static inline u32 reg_read32(struct xrp_hw_simple *hw, unsigned addr)
{
	if (hw->regs)
		return __raw_readl(hw->regs + addr);
	else
		return 0;
}

static void *get_hw_sync_data(void *hw_arg, size_t *sz)
{
	static const u32 irq_mode[] = {
		[XRP_IRQ_NONE] = XRP_DSP_SYNC_IRQ_MODE_NONE,
		[XRP_IRQ_LEVEL] = XRP_DSP_SYNC_IRQ_MODE_LEVEL,
		[XRP_IRQ_EDGE] = XRP_DSP_SYNC_IRQ_MODE_EDGE,
		[XRP_IRQ_EDGE_SW] = XRP_DSP_SYNC_IRQ_MODE_EDGE,
	};
	struct xrp_hw_simple *hw = hw_arg;
	struct xrp_hw_simple_sync_data *hw_sync_data =
		kmalloc(sizeof(*hw_sync_data), GFP_KERNEL);

	if (!hw_sync_data)
		return NULL;

	*hw_sync_data = (struct xrp_hw_simple_sync_data){
		.device_mmio_base = hw->regs_phys,
		.host_irq_mode = hw->host_irq_mode,
		.host_irq_offset = hw->host_irq[0],
		.host_irq_bit = hw->host_irq[1],
		.device_irq_mode = irq_mode[hw->device_irq_mode],
		.device_irq_offset = hw->device_irq[0],
		.device_irq_bit = hw->device_irq[1],
		.device_irq = hw->device_irq[2],
	};
	*sz = sizeof(*hw_sync_data);
	return hw_sync_data;
}

static void reset(void *hw_arg)
{
	reg_write32(hw_arg, XRP_REG_RESET, 1);
	udelay(1);
	reg_write32(hw_arg, XRP_REG_RESET, 0);
}

static void xrp_hw_simple_halt(void *hw_arg)
{
	reg_write32(hw_arg, XRP_REG_RUNSTALL, 1);
}

static void release(void *hw_arg)
{
	reg_write32(hw_arg, XRP_REG_RUNSTALL, 0);
}

static void send_irq(void *hw_arg)
{
	struct xrp_hw_simple *hw = hw_arg;

	switch (hw->device_irq_mode) {
	case XRP_IRQ_EDGE_SW:
		reg_write32(hw, hw->device_irq_host_offset,
			    BIT(hw->device_irq[1]));
		while ((reg_read32(hw, hw->device_irq_host_offset) &
			BIT(hw->device_irq[1])))
			mb();
		break;
	case XRP_IRQ_EDGE:
		reg_write32(hw, hw->device_irq_host_offset, 0);
		/* fallthrough */
	case XRP_IRQ_LEVEL:
		wmb();
		reg_write32(hw, hw->device_irq_host_offset,
			    BIT(hw->device_irq[1]));
		break;
	default:
		break;
	}
}

static void ack_irq(void *hw_arg)
{
	struct xrp_hw_simple *hw = hw_arg;

	if (hw->host_irq_mode == XRP_IRQ_LEVEL)
		reg_write32(hw, hw->host_irq[0], 0);
}

static irqreturn_t irq_handler(int irq, void *dev_id)
{
	struct xrp_hw_simple *hw = dev_id;
	irqreturn_t ret = xrp_irq_handler(irq, hw->xrp);

	if (ret == IRQ_HANDLED)
		ack_irq(hw);

	return ret;
}

#if defined(__XTENSA__)
static bool cacheable(void *hw_arg, unsigned long pfn, unsigned long n_pages)
{
	return true;
}

static void dma_sync_for_device(void *hw_arg,
				void *vaddr, phys_addr_t paddr,
				unsigned long sz, unsigned flags)
{
	switch (flags) {
	case XRP_FLAG_READ:
		__flush_dcache_range((unsigned long)vaddr, sz);
		break;

	case XRP_FLAG_READ_WRITE:
		__flush_dcache_range((unsigned long)vaddr, sz);
		__invalidate_dcache_range((unsigned long)vaddr, sz);
		break;

	case XRP_FLAG_WRITE:
		__invalidate_dcache_range((unsigned long)vaddr, sz);
		break;
	}
}

static void dma_sync_for_cpu(void *hw_arg,
			     void *vaddr, phys_addr_t paddr,
			     unsigned long sz, unsigned flags)
{
	switch (flags) {
	case XRP_FLAG_READ_WRITE:
	case XRP_FLAG_WRITE:
		__invalidate_dcache_range((unsigned long)vaddr, sz);
		break;
	}
}

#elif defined(__arm__)
static bool cacheable(void *hw_arg, unsigned long pfn, unsigned long n_pages)
{
	return true;
}

static void dma_sync_for_device(void *hw_arg,
				void *vaddr, phys_addr_t paddr,
				unsigned long sz, unsigned flags)
{
	switch (flags) {
	case XRP_FLAG_READ:
		__cpuc_flush_dcache_area(vaddr, sz);
		outer_clean_range(paddr, paddr + sz);
		break;

	case XRP_FLAG_WRITE:
		__cpuc_flush_dcache_area(vaddr, sz);
		outer_inv_range(paddr, paddr + sz);
		break;

	case XRP_FLAG_READ_WRITE:
		__cpuc_flush_dcache_area(vaddr, sz);
		outer_flush_range(paddr, paddr + sz);
		break;
	}
}

static void dma_sync_for_cpu(void *hw_arg,
			     void *vaddr, phys_addr_t paddr,
			     unsigned long sz, unsigned flags)
{
	switch (flags) {
	case XRP_FLAG_WRITE:
	case XRP_FLAG_READ_WRITE:
		__cpuc_flush_dcache_area(vaddr, sz);
		outer_inv_range(paddr, paddr + sz);
		break;
	}
}
#endif

static const struct xrp_hw_ops hw_ops = {
	.halt = xrp_hw_simple_halt,
	.release = release,
	.reset = reset,

	.get_hw_sync_data = get_hw_sync_data,

	.send_irq = send_irq,

#if defined(__XTENSA__) || defined(__arm__)
	.cacheable = cacheable,
	.dma_sync_for_device = dma_sync_for_device,
	.dma_sync_for_cpu = dma_sync_for_cpu,
#endif
};

static long init_hw(struct platform_device *pdev, struct xrp_hw_simple *hw,
		    int mem_idx, enum xrp_init_flags *init_flags)
{
	struct resource *mem;
	int irq;
	long ret;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, mem_idx);
	if (!mem) {
		ret = -ENODEV;
		goto err;
	}
	hw->regs_phys = mem->start;
	hw->regs = devm_ioremap_resource(&pdev->dev, mem);
	pr_debug("%s: regs = %pap/%p\n",
		 __func__, &mem->start, hw->regs);

	ret = device_property_read_u32_array(&pdev->dev,
					     "device-irq",
					     hw->device_irq,
					     ARRAY_SIZE(hw->device_irq));
	if (ret == 0) {
		u32 device_irq_host_offset;

		ret = device_property_read_u32(&pdev->dev,
					       "device-irq-host-offset",
					       &device_irq_host_offset);
		if (ret == 0) {
			hw->device_irq_host_offset = device_irq_host_offset;
		} else {
			hw->device_irq_host_offset = hw->device_irq[0];
			ret = 0;
		}
	}
	if (ret == 0) {
		u32 device_irq_mode;

		ret = device_property_read_u32(&pdev->dev,
					       "device-irq-mode",
					       &device_irq_mode);
		if (device_irq_mode < XRP_IRQ_MAX)
			hw->device_irq_mode = device_irq_mode;
		else
			ret = -ENOENT;
	}
	if (ret == 0) {
		dev_dbg(&pdev->dev,
			"%s: device IRQ MMIO host offset = 0x%08x, offset = 0x%08x, bit = %d, device IRQ = %d, IRQ mode = %d",
			__func__, hw->device_irq_host_offset,
			hw->device_irq[0], hw->device_irq[1],
			hw->device_irq[2], hw->device_irq_mode);
	} else {
		dev_info(&pdev->dev,
			 "using polling mode on the device side\n");
	}

	ret = device_property_read_u32_array(&pdev->dev, "host-irq",
					     hw->host_irq,
					     ARRAY_SIZE(hw->host_irq));
	if (ret == 0) {
		u32 host_irq_mode;

		ret = device_property_read_u32(&pdev->dev,
					       "host-irq-mode",
					       &host_irq_mode);
		if (host_irq_mode < XRP_IRQ_MAX)
			hw->host_irq_mode = host_irq_mode;
		else
			ret = -ENOENT;
	}

	if (ret == 0 && hw->host_irq_mode != XRP_IRQ_NONE)
		irq = platform_get_irq(pdev, 0);
	else
		irq = -1;

	if (irq >= 0) {
		dev_dbg(&pdev->dev, "%s: host IRQ = %d, ",
			__func__, irq);
		ret = devm_request_irq(&pdev->dev, irq, irq_handler,
				       IRQF_SHARED, pdev->name, hw);
		if (ret < 0) {
			dev_err(&pdev->dev, "request_irq %d failed\n", irq);
			goto err;
		}
		*init_flags |= XRP_INIT_USE_HOST_IRQ;
	} else {
		dev_info(&pdev->dev, "using polling mode on the host side\n");
	}
	ret = 0;
err:
	return ret;
}

static long init(struct platform_device *pdev, struct xrp_hw_simple *hw)
{
	long ret;
	enum xrp_init_flags init_flags = 0;

	ret = init_hw(pdev, hw, 0, &init_flags);
	if (ret < 0)
		return ret;

	return xrp_init(pdev, init_flags, &hw_ops, hw);
}

static long init_v1(struct platform_device *pdev, struct xrp_hw_simple *hw)
{
	long ret;
	enum xrp_init_flags init_flags = 0;

	ret = init_hw(pdev, hw, 1, &init_flags);
	if (ret < 0)
		return ret;

	return xrp_init_v1(pdev, init_flags, &hw_ops, hw);
}

static long init_cma(struct platform_device *pdev, struct xrp_hw_simple *hw)
{
	long ret;
	enum xrp_init_flags init_flags = 0;

	ret = init_hw(pdev, hw, 0, &init_flags);
	if (ret < 0)
		return ret;

	return xrp_init_cma(pdev, init_flags, &hw_ops, hw);
}

#ifdef CONFIG_OF
static const struct of_device_id xrp_hw_simple_match[] = {
	{
		.compatible = "cdns,xrp-hw-simple",
		.data = init,
	}, {
		.compatible = "cdns,xrp-hw-simple,v1",
		.data = init_v1,
	}, {
		.compatible = "cdns,xrp-hw-simple,cma",
		.data = init_cma,
	}, {},
};
MODULE_DEVICE_TABLE(of, xrp_hw_simple_match);
#endif

static int xrp_hw_simple_probe(struct platform_device *pdev)
{
	struct xrp_hw_simple *hw =
		devm_kzalloc(&pdev->dev, sizeof(*hw), GFP_KERNEL);
	const struct of_device_id *match;
	long (*init)(struct platform_device *pdev, struct xrp_hw_simple *hw);
	long ret;

	if (!hw)
		return -ENOMEM;

	match = of_match_device(of_match_ptr(xrp_hw_simple_match),
				&pdev->dev);
	if (!match)
		return -ENODEV;

	init = match->data;
	ret = init(pdev, hw);
	if (IS_ERR_VALUE(ret)) {
		xrp_deinit(pdev);
		return ret;
	} else {
		hw->xrp = ERR_PTR(ret);
		return 0;
	}

}

static int xrp_hw_simple_remove(struct platform_device *pdev)
{
	return xrp_deinit(pdev);
}

static const struct dev_pm_ops xrp_hw_simple_pm_ops = {
	SET_RUNTIME_PM_OPS(xrp_runtime_suspend,
			   xrp_runtime_resume, NULL)
};

static struct platform_driver xrp_hw_simple_driver = {
	.probe   = xrp_hw_simple_probe,
	.remove  = xrp_hw_simple_remove,
	.driver  = {
		.name = DRIVER_NAME,
		.of_match_table = of_match_ptr(xrp_hw_simple_match),
		.pm = &xrp_hw_simple_pm_ops,
	},
};

module_platform_driver(xrp_hw_simple_driver);

MODULE_AUTHOR("Max Filippov");
MODULE_DESCRIPTION("XRP: low level device driver for Xtensa Remote Processing");
MODULE_LICENSE("Dual MIT/GPL");
