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

	void (*clean_cache)(void *vaddr, phys_addr_t paddr, unsigned long sz);
	void (*flush_cache)(void *vaddr, phys_addr_t paddr, unsigned long sz);
	void (*invalidate_cache)(void *vaddr, phys_addr_t paddr,
				 unsigned long sz);
};

int xrp_init(struct platform_device *pdev, struct xvp *xvp,
	     const struct xrp_hw_ops *hw, void *hw_arg);
int xrp_init_v1(struct platform_device *pdev, struct xvp *xvp,
		const struct xrp_hw_ops *hw, void *hw_arg);

int xrp_deinit(struct platform_device *pdev);
irqreturn_t xrp_irq_handler(int irq, struct xvp *xvp);
int xrp_runtime_resume(struct device *dev);
int xrp_runtime_suspend(struct device *dev);

#endif
