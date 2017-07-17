/*
 * Internal XRP structures definition.
 *
 * Copyright (c) 2015 - 2017 Cadence Design Systems, Inc.
 *
 * License: Dual MIT/GPL.
 */

#ifndef XRP_INTERNAL_H
#define XRP_INTERNAL_H

#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include "xrp_address_map.h"
#include "xrp_alloc.h"

struct device;
struct firmware;
struct xrp_hw_ops;

struct xvp {
	struct device *dev;
	const char *firmware_name;
	const struct firmware *firmware;
	struct miscdevice miscdev;
	const struct xrp_hw_ops *hw_ops;
	void *hw_arg;

	void __iomem *comm;
	phys_addr_t pmem;
	phys_addr_t comm_phys;

	struct xrp_address_map address_map;

	bool host_irq_mode;
	struct completion completion;

	struct xrp_allocation_pool pool;
	struct mutex comm_lock;
};

#endif
