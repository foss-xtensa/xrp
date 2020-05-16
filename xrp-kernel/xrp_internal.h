/*
 * Internal XRP structures definition.
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

#ifndef XRP_INTERNAL_H
#define XRP_INTERNAL_H

#include <linux/completion.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include "xrp_address_map.h"

struct device;
struct firmware;
struct xrp_hw_ops;
struct xrp_allocation_pool;

struct xrp_comm {
	struct mutex lock;
	void __iomem *comm;
	struct completion completion;
	u32 priority;
};

struct xvp {
	struct device *dev;
	const char *firmware_name;
	const struct firmware *firmware;
	struct miscdevice miscdev;
	const struct xrp_hw_ops *hw_ops;
	void *hw_arg;
	unsigned n_queues;

	u32 *queue_priority;
	struct xrp_comm *queue;
	struct xrp_comm **queue_ordered;
	void __iomem *comm;
	phys_addr_t pmem;
	phys_addr_t comm_phys;
	phys_addr_t shared_size;
	atomic_t reboot_cycle;
	atomic_t reboot_cycle_complete;

	struct xrp_address_map address_map;

	bool host_irq_mode;

	struct xrp_allocation_pool *pool;
	bool off;
	int nodeid;
	bool direct_mapping;
};

#endif
