/*
 * xrp_hw: interface between hardware-specific and generic parts of XRP
 *
 * Copyright (c) 2017 Cadence Design Systems, Inc.
 *
 * License: Dual MIT/GPL.
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

int xrp_deinit(struct platform_device *pdev);
irqreturn_t xrp_irq_handler(int irq, struct xvp *xvp);

#endif
