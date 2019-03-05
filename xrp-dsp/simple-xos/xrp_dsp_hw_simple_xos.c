/*
 * Copyright (c) 2019 Cadence Design Systems Inc.
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
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtensa/hal.h>
#include <xtensa/xos.h>

#include "xrp_debug.h"
#include "xrp_dsp_hw.h"
#include "xrp_dsp_interrupt.h"
#include "xrp_dsp_sync.h"
#include "xrp_dsp_user.h"
#include "xrp_types.h"
#include "xrp_hw_simple_dsp_interface.h"

extern char xrp_user_queue_stack_size[] __attribute__((weak));
static uint32_t mmio_base;

#define device_mmio(off) ((volatile void *)mmio_base + off)
#define host_mmio(off) ((volatile void *)mmio_base + off)

enum xrp_irq_mode {
	XRP_IRQ_NONE,
	XRP_IRQ_LEVEL,
	XRP_IRQ_EDGE,
};
static enum xrp_irq_mode host_irq_mode;
static enum xrp_irq_mode device_irq_mode;

static uint32_t device_irq_offset;
static uint32_t device_irq_bit;
static uint32_t device_irq;

static uint32_t host_irq_offset;
static uint32_t host_irq_bit;

static unsigned n_queues;
struct dsp_queue {
	struct xrp_device *device;
	XosSem sem;
	XosMutex comm_lock;
	XosThread thread;
	volatile int exit;
	void *stack;
};
static struct dsp_queue queue0, *queue;

/*
 * Try to avoid waking up queue thread needlessly.
 * Particularly don't wake it up just to check the queue status.
 * Instead check status here by calling xrp_device_poll.
 * But xrp_device_poll may involve cache invalidation on the
 * comm area, we can only do it in coordination with the queue
 * thread. Protect comm area by mutex and only poll if the mutex
 * was successfully taken, otherwise the thread is using the comm
 * area right now, so we won't wake it up by signaling the semaphore.
 */
static void check_queue(struct dsp_queue *q)
{
	if (xos_thread_id() == &q->thread) {
		pr_debug("%s: waking up queue %p (current)\n",
			 __func__, q);
		xos_sem_put_max(&q->sem, 1);
	} else if (xos_mutex_test(&q->comm_lock) == 0) {
		if (xrp_device_poll(q->device) == XRP_STATUS_SUCCESS) {
			pr_debug("%s: waking up queue %p (got lock)\n",
				 __func__, q);
			xos_sem_put_max(&q->sem, 1);
		}
	} else {
		pr_debug("%s: waking up queue %p\n", __func__, q);
		xos_sem_put_max(&q->sem, 1);
	}
}

static void xrp_clear_device_irq(void)
{
	if (device_irq_mode == XRP_IRQ_LEVEL)
		xrp_s32ri(0, device_mmio(device_irq_offset));
}

static void xrp_irq_handler(void *p)
{
	unsigned i;

	(void)p;
	pr_debug("%s [%p]\n", __func__, xos_thread_id());
	xrp_clear_device_irq();

	if (n_queues == 1)
		xos_sem_put_max(&queue0.sem, 1);
	else
		check_queue(&queue0);

	for (i = 1; i < n_queues; ++i)
		check_queue(queue + i - 1);
}

void xrp_hw_send_host_irq(void)
{
	switch (host_irq_mode) {
	case XRP_IRQ_EDGE:
		xrp_s32ri(0, host_mmio(host_irq_offset));
		/* fall through */
	case XRP_IRQ_LEVEL:
		xrp_s32ri(1u << host_irq_bit, host_mmio(host_irq_offset));
		break;
	default:
		break;
	}
}

static void xrp_irq_probe_handler(void *p)
{
	(void)p;
	pr_debug("%s\n", __func__);
	xrp_clear_device_irq();
	xos_sem_put_max(&queue0.sem, 1);
}

void xrp_hw_wait_device_irq(void)
{
	if (device_irq_mode == XRP_IRQ_NONE)
		return;

	pr_debug("%s [%p]: waiting for device IRQ...\n",
		 __func__, xos_thread_id());
	xos_sem_get(&queue0.sem);
	xos_register_interrupt_handler(device_irq, xrp_irq_handler,
				       NULL);
}

void xrp_hw_set_sync_data(void *p)
{
	static const enum xrp_irq_mode irq_mode[] = {
		[XRP_DSP_SYNC_IRQ_MODE_NONE] = XRP_IRQ_NONE,
		[XRP_DSP_SYNC_IRQ_MODE_LEVEL] = XRP_IRQ_LEVEL,
		[XRP_DSP_SYNC_IRQ_MODE_EDGE] = XRP_IRQ_EDGE,
	};
	struct xrp_hw_simple_sync_data *hw_sync = p;

	mmio_base = hw_sync->device_mmio_base;
	pr_debug("%s: mmio_base: 0x%08x\n", __func__, mmio_base);

	if (hw_sync->device_irq_mode < sizeof(irq_mode) / sizeof(*irq_mode)) {
		device_irq_mode = irq_mode[hw_sync->device_irq_mode];
		device_irq_offset = hw_sync->device_irq_offset;
		device_irq_bit = hw_sync->device_irq_bit;
		device_irq = hw_sync->device_irq;
		pr_debug("%s: device_irq_mode = %d, device_irq_offset = %d, device_irq_bit = %d, device_irq = %d\n",
			__func__, device_irq_mode,
			device_irq_offset, device_irq_bit, device_irq);
	} else {
		device_irq_mode = XRP_IRQ_NONE;
	}

	if (hw_sync->host_irq_mode < sizeof(irq_mode) / sizeof(*irq_mode)) {
		host_irq_mode = irq_mode[hw_sync->host_irq_mode];
		host_irq_offset = hw_sync->host_irq_offset;
		host_irq_bit = hw_sync->host_irq_bit;
		pr_debug("%s: host_irq_mode = %d, host_irq_offset = %d, host_irq_bit = %d\n",
			__func__, host_irq_mode, host_irq_offset, host_irq_bit);
	} else {
		host_irq_mode = XRP_IRQ_NONE;
	}

	if (device_irq_mode != XRP_IRQ_NONE) {
#if XCHAL_HAVE_XEA3
		xthal_interrupt_sens_set(device_irq,
					 device_irq_mode == XRP_IRQ_LEVEL);
#endif
		xos_register_interrupt_handler(device_irq,
					       xrp_irq_probe_handler, NULL);
		xos_interrupt_enable(device_irq);
	}
}

void xrp_hw_panic(void)
{
}

void xrp_hw_init(void)
{
}

static int32_t queue_thread(void *p, int32_t wake_value)
{
	struct dsp_queue *q = p;

	(void)wake_value;
	pr_debug("%s [%p]: queue = %p\n", __func__, xos_thread_id(), q);

	xos_mutex_lock(&q->comm_lock);
	while (!q->exit) {
		if (xrp_device_dispatch(q->device) == XRP_STATUS_PENDING) {
			xos_mutex_unlock(&q->comm_lock);
			if (device_irq_mode == XRP_IRQ_NONE)
				xos_thread_yield();
			else
				xos_sem_get(&q->sem);
			xos_mutex_lock(&q->comm_lock);
		}
	}
	xos_mutex_unlock(&q->comm_lock);
	return 0;
}

static int start_queue(struct dsp_queue *q, unsigned stack_size,
		       uint32_t priority)
{
	int32_t rv;

	pr_debug("%s: priority = %d\n", __func__, priority);
	q->exit = 0;
	q->stack = malloc(stack_size);
	if (q->stack == NULL)
		goto err;
	rv = xos_sem_create(&q->sem, XOS_SEM_WAIT_FIFO, 0);
	if (rv != XOS_OK)
		goto err;
	rv = xos_mutex_create(&q->comm_lock, XOS_MUTEX_WAIT_FIFO, 0);
	if (rv != XOS_OK)
		goto err_sem;
	rv = xos_thread_create(&q->thread, NULL, queue_thread, q,
			       "xrp_queue_thread", q->stack, stack_size,
			       priority, NULL, 0);
	if (rv == XOS_OK)
		return 1;

	xos_mutex_delete(&q->comm_lock);
err_sem:
	xos_sem_delete(&q->sem);
err:
	free(q->stack);
	return 0;
}

static void stop_queue(struct dsp_queue *q)
{
	q->exit = 1;
	xos_sem_put(&q->sem);
	xos_thread_join(&q->thread, NULL);
	xos_sem_delete(&q->sem);
	xos_mutex_delete(&q->comm_lock);
	xos_thread_delete(&q->thread);
	free(q->stack);
}

static void stop_all_queues(void)
{
	unsigned i;

	for (i = 1; i < n_queues; ++i)
		stop_queue(queue + i - 1);
	n_queues = 1;
}

enum xrp_status xrp_user_create_queues(unsigned n, uint32_t priority[])
{
	unsigned i;
	unsigned stack_size = (unsigned)&xrp_user_queue_stack_size;

	if (!stack_size)
		stack_size = 0x2000 + XOS_STACK_EXTRA;

	if (n_queues == 0) {
		queue0.device = xrp_open_device(0, NULL);
		if (!start_queue(&queue0, stack_size, priority[0]))
			return XRP_STATUS_FAILURE;
		n_queues = 1;
	} else {
		if (xos_thread_set_priority(&queue0.thread,
					    priority[0]) != XOS_OK)
			goto err;
	}

	if (n > 1 && device_irq_mode == XRP_IRQ_NONE)
		goto err;

	if (n > n_queues) {
		struct dsp_queue *q = calloc(n - 1, sizeof(struct dsp_queue));

		if (!q)
			goto err;
		stop_all_queues();
		free(queue);
		queue = q;
		for (i = n_queues; i < n; ++i) {
			queue[i - 1].device = xrp_open_device(i, NULL);
			if (!start_queue(queue + i - 1, stack_size, priority[i]))
				goto err;
			++n_queues;
		}
	} else {
		for (i = n; i < n_queues; ++i)
			stop_queue(queue + i - 1);
		n_queues = n;
		for (i = 1; i < n_queues; ++i)
			if (xos_thread_set_priority(&queue[i - 1].thread,
						    priority[i]) != XOS_OK)
				goto err;
	}
	return XRP_STATUS_SUCCESS;

err:
	stop_all_queues();
	free(queue);
	queue = NULL;
	return XRP_STATUS_FAILURE;
}
