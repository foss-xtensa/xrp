/*
 * xrp_hw: interface between hardware-specific and generic parts of XRP
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

#ifndef _XRP_HW
#define _XRP_HW

#include <linux/irqreturn.h>
#include <linux/platform_device.h>
#include <linux/types.h>

struct xvp;

struct xrp_hw_ops {
	/* enable power/clock, but keep the core stalled */
	int (*enable)(void *hw_arg);
	/* diable power/clock */
	void (*disable)(void *hw_arg);
	/* reset the core */
	void (*reset)(void *hw_arg);
	/* unstall the core */
	void (*release)(void *hw_arg);
	/* stall the core */
	void (*halt)(void *hw_arg);

	void *(*get_hw_sync_data)(void *hw_arg, size_t *sz);

	/* send IRQ to the core */
	void (*send_irq)(void *hw_arg);

	/*
	 * check whether region of physical memory may be handled by
	 * dma_sync_* operations
	 */
	bool (*cacheable)(void *hw_arg, unsigned long pfn, unsigned long n_pages);
	/*
	 * synchronize region of memory for DSP access.
	 * flags: XRP_FLAG_{READ,WRITE,READWRITE}
	 */
	void (*dma_sync_for_device)(void *hw_arg,
				    void *vaddr, phys_addr_t paddr,
				    unsigned long sz, unsigned flags);
	/*
	 * synchronize region of memory for host access.
	 * flags: XRP_FLAG_{READ,WRITE,READWRITE}
	 */
	void (*dma_sync_for_cpu)(void *hw_arg,
				 void *vaddr, phys_addr_t paddr,
				 unsigned long sz, unsigned flags);

	/* memcpy data/code to device-specific memory */
	void (*memcpy_tohw)(void __iomem *dst, const void *src, size_t sz);
	/* memset device-specific memory */
	void (*memset_hw)(void __iomem *dst, int c, size_t sz);

	/* check DSP status */
	bool (*panic_check)(void *hw_arg);
};

enum xrp_init_flags {
	XRP_INIT_USE_HOST_IRQ = 0x1,
};

long xrp_init(struct platform_device *pdev, enum xrp_init_flags flags,
	      const struct xrp_hw_ops *hw, void *hw_arg);
long xrp_init_v1(struct platform_device *pdev, enum xrp_init_flags flags,
		 const struct xrp_hw_ops *hw, void *hw_arg);
long xrp_init_cma(struct platform_device *pdev, enum xrp_init_flags flags,
		  const struct xrp_hw_ops *hw, void *hw_arg);

int xrp_deinit(struct platform_device *pdev);
int xrp_deinit_hw(struct platform_device *pdev, void **hw_arg);
irqreturn_t xrp_irq_handler(int irq, struct xvp *xvp);
int xrp_runtime_resume(struct device *dev);
int xrp_runtime_suspend(struct device *dev);

#endif
