/*
 * Copyright (c) 2016 - 2018 Cadence Design Systems Inc.
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

#include <libfdt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_DEFINED(a, b) ((void)(a),(void)(b))
#endif

#define barrier() asm volatile ("" ::: "memory")
#define mb() barrier()
#define schedule() barrier()

typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;

#include "xrp_debug.h"
#include "xrp_host_common.h"
#include "xrp_host_impl.h"
#include "xrp_kernel_dsp_interface.h"
#include "xrp_hw_simple_dsp_interface.h"
#include "xrp_private_alloc.h"
#include "xrp_host.h"

enum {
	XRP_IRQ_NONE,
	XRP_IRQ_LEVEL,
	XRP_IRQ_EDGE,
	XRP_IRQ_MAX,
};

extern char dt_blob_start[];

struct xrp_device_description {
	phys_addr_t io_base;
	phys_addr_t comm_base;
	phys_addr_t shared_base;
	phys_addr_t shared_size;
	void *comm_ptr;
	void *shared_ptr;

	uint32_t device_irq_mode;
	uint32_t device_irq[3];
	uint32_t device_irq_host_offset;
	xrp_mutex hw_mutex;
	struct xrp_allocation_pool *shared_pool;
	int sync;
};

static struct xrp_device_description xrp_device_description[4];
static int xrp_device_count;

struct xrp_request {
	struct xrp_queue_item q;
	struct xrp_dsp_cmd dsp_cmd;

	size_t n_buffers;
	size_t in_data_size;
	void *out_data;
	void *out_data_ptr;
	size_t out_data_size;
	struct xrp_buffer_group *buffer_group;
	struct xrp_event *event;

	struct xrp_allocation *in_data_allocation;
	struct xrp_allocation *out_data_allocation;
	struct xrp_allocation *buffer_allocation;
	struct xrp_allocation **user_buffer_allocation;
	struct xrp_dsp_buffer *buffer_ptr;
};

/* Helpers */

static uint32_t getprop_u32(const void *value, int offset)
{
	fdt32_t v;

	memcpy(&v, value + offset, sizeof(v));
	return fdt32_to_cpu(v);
}

static inline void xrp_comm_write32(volatile void *addr, __u32 v)
{
	pr_debug("%s: 0x%08x, %08x\n", __func__, v2p((const void *)addr), v);
	*(volatile __u32 *)addr = v;
}

static inline __u32 xrp_comm_read32(const volatile void *addr)
{
	return *(volatile __u32 *)addr;
}

static inline void xrp_send_device_irq(struct xrp_device_description *desc)
{
	void *device_irq = p2v(desc->io_base + desc->device_irq_host_offset);

	switch (desc->device_irq_mode) {
	case XRP_IRQ_EDGE:
		xrp_comm_write32(device_irq, 0);
		/* fallthrough */
	case XRP_IRQ_LEVEL:
		mb();
		xrp_comm_write32(device_irq, 1 << desc->device_irq[1]);
		break;
	default:
		break;
	}
}

static void synchronize(struct xrp_device_description *desc)
{
	static const int irq_mode[] = {
		[XRP_IRQ_NONE] = XRP_DSP_SYNC_IRQ_MODE_NONE,
		[XRP_IRQ_LEVEL] = XRP_DSP_SYNC_IRQ_MODE_LEVEL,
		[XRP_IRQ_EDGE] = XRP_DSP_SYNC_IRQ_MODE_EDGE,
	};

	struct xrp_dsp_sync *shared_sync = desc->comm_ptr;
	struct xrp_hw_simple_sync_data *hw_sync =
		(struct xrp_hw_simple_sync_data *)&shared_sync->hw_sync_data;

	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_START);
	mb();
	xrp_send_device_irq(desc);
	do {
		__u32 v = xrp_comm_read32(&shared_sync->sync);
		if (v == XRP_DSP_SYNC_DSP_READY)
			break;
		schedule();
	} while (1);

	xrp_comm_write32(&hw_sync->device_mmio_base,
			 desc->io_base);
	xrp_comm_write32(&hw_sync->host_irq_mode,
			 irq_mode[0]);
	xrp_comm_write32(&hw_sync->host_irq_offset,
			 0);
	xrp_comm_write32(&hw_sync->host_irq_bit,
			 0);
	xrp_comm_write32(&hw_sync->device_irq_mode,
			 irq_mode[desc->device_irq_mode]);
	xrp_comm_write32(&hw_sync->device_irq_offset,
			 desc->device_irq[0]);
	xrp_comm_write32(&hw_sync->device_irq_bit,
			 desc->device_irq[1]);
	xrp_comm_write32(&hw_sync->device_irq,
			 desc->device_irq[2]);
	mb();
	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_HOST_TO_DSP);
	mb();

	do {
		__u32 v = xrp_comm_read32(&shared_sync->sync);
		if (v == XRP_DSP_SYNC_DSP_TO_HOST)
			break;
		schedule();
	} while (1);

	xrp_send_device_irq(desc);

#if 0
	if (xvp->host_irq_mode != XRP_IRQ_NONE) {
		int res = wait_for_completion_timeout(&xvp->completion,
						      XVP_TIMEOUT_JIFFIES);
		if (res == 0) {
			dev_err(xvp->dev,
				"host IRQ mode is requested, but DSP couldn't deliver IRQ during synchronization\n");
			goto err;
		}
	}
#endif
	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_IDLE);

	desc->sync = 1;
}

struct of_node_match {
	const char *compatible;
	int (*init)(void *fdt, int offset,
		    struct xrp_device_description *description);
};

static int init_cdns_xrp_common(struct xrp_device_description *description)
{
	description->comm_ptr = p2v(description->comm_base);
	if (!description->comm_ptr) {
		printf("%s: shmem not found for comm area @0x%08x\n",
		       __func__, description->comm_base);
		return 0;
	}

	description->shared_ptr = p2v(description->shared_base);
	if (!description->shared_ptr) {
		printf("%s: shmem not found for shared area @0x%08x\n",
		       __func__, description->shared_base);
		return 0;
	}
	xrp_init_private_pool(&description->shared_pool,
			      description->shared_base,
			      description->shared_size);
	return 1;
}

static int init_cdns_xrp(void *fdt, int offset,
			 struct xrp_device_description *description)
{
	const void *reg;
	int len;

	reg = fdt_getprop(fdt, offset, "reg", &len);
	if (!reg) {
		printf("%s: %s\n", __func__, fdt_strerror(len));
		return 0;
	}
	if (len < 24) {
		printf("%s: reg property size is too small (%d)\n",
		       __func__, len);
		return 0;
	}

	*description = (struct xrp_device_description){
		.io_base = getprop_u32(reg, 0),
		.comm_base = getprop_u32(reg, 8),
		.shared_base = getprop_u32(reg, 16),
		.shared_size = getprop_u32(reg, 20),
	};
	xrp_mutex_init(&description->hw_mutex);
	return init_cdns_xrp_common(description);
}

static int init_cdns_xrp_v1(void *fdt, int offset,
			    struct xrp_device_description *description)
{
	const void *reg;
	int len;

	reg = fdt_getprop(fdt, offset, "reg", &len);
	if (!reg) {
		printf("%s: %s\n", __func__, fdt_strerror(len));
		return 0;
	}
	if (len < 16) {
		printf("%s: reg property size is too small (%d)\n",
		       __func__, len);
		return 0;
	}

	*description = (struct xrp_device_description){
		.comm_base = getprop_u32(reg, 0),
		.shared_base = getprop_u32(reg, 0) + 4096,
		.shared_size = getprop_u32(reg, 4) - 4096,
		.io_base = getprop_u32(reg, 8),
	};
	xrp_mutex_init(&description->hw_mutex);
	return init_cdns_xrp_common(description);
}

static int init_cdns_xrp_hw_simple_common(void *fdt, int offset,
					  struct xrp_device_description *description)
{
	const void *device_irq;
	const void *device_irq_host_offset;
	const void *device_irq_mode;
	int len;

	device_irq_mode = fdt_getprop(fdt, offset, "device-irq-mode", &len);
	if (!device_irq_mode || len < 4) {
		printf("%s: valid device-irq-mode not found, not using\n",
		       __func__);
		device_irq_mode = NULL;
	}
	if (device_irq_mode && getprop_u32(device_irq_mode, 0)) {
		device_irq = fdt_getprop(fdt, offset, "device-irq", &len);
		if (!device_irq || len < 12) {
			printf("%s: valid device-irq not found, not using\n",
			       __func__);
			device_irq_mode = NULL;
			device_irq = NULL;
		} else {
			description->device_irq_mode =
				getprop_u32(device_irq_mode, 0);
			description->device_irq[0] =
				getprop_u32(device_irq, 0);
			description->device_irq[1] =
				getprop_u32(device_irq, 4);
			description->device_irq[2] =
				getprop_u32(device_irq, 8);

			device_irq_host_offset = fdt_getprop(fdt, offset,
							     "device-irq-host-offset",
							     &len);
			if (!device_irq_host_offset || len < 4) {
				description->device_irq_host_offset =
					description->device_irq[0];
				printf("%s: valid device-irq-host-offset not found, not using\n",
				       __func__);
			} else {
				description->device_irq_host_offset =
					getprop_u32(device_irq_host_offset, 0);
			}
		}
	}
	return 1;
}

static int init_cdns_xrp_hw_simple(void *fdt, int offset,
				   struct xrp_device_description *description)
{
	return init_cdns_xrp(fdt, offset, description) &&
		init_cdns_xrp_hw_simple_common(fdt, offset, description);
}

static int init_cdns_xrp_hw_simple_v1(void *fdt, int offset,
				      struct xrp_device_description *description)
{
	return init_cdns_xrp_v1(fdt, offset, description) &&
		init_cdns_xrp_hw_simple_common(fdt, offset, description);
}

static void initialize(void)
{
	int offset = -1;
	void *fdt = &dt_blob_start;
	static const struct of_node_match of_match[] = {
		{
			.compatible = "cdns,xrp",
			.init = init_cdns_xrp
		}, {
			.compatible = "cdns,xrp,v1",
			.init = init_cdns_xrp_v1
		}, {
			.compatible = "cdns,xrp-hw-simple",
			.init = init_cdns_xrp_hw_simple,
		}, {
			.compatible = "cdns,xrp-hw-simple,v1",
			.init = init_cdns_xrp_hw_simple_v1,
		}, {
			.compatible = NULL, /* last entry */
		}
	};
	const struct of_node_match *match = of_match;

	xrp_initialize_shmem();

	for (;;) {
		int ret;
		offset = fdt_node_offset_by_compatible(fdt,
						       offset,
						       match->compatible);
		if (offset < 0) {
			if (!(++match)->compatible)
				break;
			offset = -1;
			continue;
		}

		ret = match->init(fdt, offset,
				  xrp_device_description + xrp_device_count);
		if (ret == 0)
			continue;

		++xrp_device_count;
	}
}

/* Device API. */

static void xrp_request_process(struct xrp_queue_item *rq,
				void *context);

struct xrp_device *xrp_open_device(int idx, enum xrp_status *status)
{
	struct xrp_device *device;

	if (!xrp_device_count)
		initialize();

	if (idx < 0 || idx >= xrp_device_count) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}
	if (!xrp_device_description[idx].sync)
		synchronize(xrp_device_description + idx);

	device = alloc_refcounted(sizeof(*device));
	if (!device) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}
	device->impl.description = xrp_device_description + idx;
	xrp_queue_init(&device->impl.queue, device, xrp_request_process);
	set_status(status, XRP_STATUS_SUCCESS);
	return device;
}

void xrp_impl_release_device(struct xrp_device *device, enum xrp_status *status)
{
	xrp_queue_destroy(&device->impl.queue);
	set_status(status, XRP_STATUS_SUCCESS);
}


/* Buffer API. */

void xrp_impl_create_device_buffer(struct xrp_device *device,
				   struct xrp_buffer *buffer,
				   size_t size,
				   enum xrp_status *status)
{
	long rc = xrp_allocate(device->impl.description->shared_pool, size,
			       0x10, &buffer->impl.xrp_allocation);
	if (rc < 0) {
		set_status(status, XRP_STATUS_FAILURE);
		return;
	}
	xrp_retain_device(device, NULL);
	buffer->device = device;
	buffer->ptr = p2v(buffer->impl.xrp_allocation->start);
	buffer->size = size;
	set_status(status, XRP_STATUS_SUCCESS);
}

void xrp_impl_release_device_buffer(struct xrp_buffer *buffer,
				    enum xrp_status *status)
{
	xrp_free(buffer->impl.xrp_allocation);
	xrp_release_device(buffer->device, NULL);
	set_status(status, XRP_STATUS_SUCCESS);
}

/* Queue API. */

void xrp_impl_create_queue(struct xrp_queue *queue,
			   enum xrp_status *status)
{
	(void)queue;
	set_status(status, XRP_STATUS_SUCCESS);
}

void xrp_impl_release_queue(struct xrp_queue *queue,
			    enum xrp_status *status)
{
	(void)queue;
	set_status(status, XRP_STATUS_SUCCESS);
}

/* Communication API */

static void _xrp_run_command(struct xrp_device *device,
			     struct xrp_request *rq)
{
	struct xrp_dsp_cmd *dsp_cmd = device->impl.description->comm_ptr;
	size_t i;

	xrp_mutex_lock(&device->impl.description->hw_mutex);
	memcpy(dsp_cmd, &rq->dsp_cmd, sizeof(rq->dsp_cmd));
	barrier();
	xrp_comm_write32(&dsp_cmd->flags,
			 rq->dsp_cmd.flags | XRP_DSP_CMD_FLAG_REQUEST_VALID);
	barrier();
	xrp_send_device_irq(device->impl.description);
	do {
		barrier();
	} while ((xrp_comm_read32(&dsp_cmd->flags) &
		  (XRP_DSP_CMD_FLAG_REQUEST_VALID |
		   XRP_DSP_CMD_FLAG_RESPONSE_VALID)) !=
		 (XRP_DSP_CMD_FLAG_REQUEST_VALID |
		  XRP_DSP_CMD_FLAG_RESPONSE_VALID));

	memcpy(&rq->dsp_cmd, dsp_cmd, sizeof(rq->dsp_cmd));
	VALGRIND_MAKE_MEM_DEFINED(rq->out_data_ptr, rq->out_data_size);
	memcpy(rq->out_data, rq->out_data_ptr, rq->out_data_size);
	xrp_mutex_unlock(&device->impl.description->hw_mutex);

	if (rq->in_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		xrp_free(rq->in_data_allocation);
	}
	if (rq->out_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		xrp_free(rq->out_data_allocation);
	}

	if (rq->buffer_group)
		xrp_mutex_lock(&rq->buffer_group->mutex);

	for (i = 0; i < rq->n_buffers; ++i) {
		phys_addr_t addr;

		if (rq->buffer_group->buffer[i].buffer->type != XRP_BUFFER_TYPE_DEVICE) {
			if (rq->buffer_ptr[i].flags & XRP_DSP_BUFFER_FLAG_WRITE) {
				addr = rq->user_buffer_allocation[i]->start;
				if (!(rq->buffer_ptr[i].flags & XRP_DSP_BUFFER_FLAG_READ))
					VALGRIND_MAKE_MEM_DEFINED(p2v(addr),
								  rq->buffer_group->buffer[i].buffer->size);
				memcpy(rq->buffer_group->buffer[i].buffer->ptr, p2v(addr),
				       rq->buffer_group->buffer[i].buffer->size);
			}
			xrp_free(rq->user_buffer_allocation[i]);
		}
	}
	if (rq->n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
		xrp_free(rq->buffer_allocation);
	}

	if (rq->buffer_group) {
		xrp_mutex_unlock(&rq->buffer_group->mutex);
		xrp_release_buffer_group(rq->buffer_group, NULL);
	}

	if (rq->event) {
		struct xrp_event *event = rq->event;
		xrp_cond_lock(&event->impl.cond);
		if (rq->dsp_cmd.flags & XRP_DSP_CMD_FLAG_RESPONSE_DELIVERY_FAIL)
			event->status = XRP_STATUS_FAILURE;
		else
			event->status = XRP_STATUS_SUCCESS;
		xrp_cond_broadcast(&event->impl.cond);
		xrp_cond_unlock(&event->impl.cond);
		xrp_release_event(event, NULL);
	}
	free(rq->user_buffer_allocation);
	free(rq);
}

static void xrp_request_process(struct xrp_queue_item *rq,
				void *context)
{
	_xrp_run_command(context, (struct xrp_request *)rq);
}

void xrp_enqueue_command(struct xrp_queue *queue,
			 const void *in_data, size_t in_data_size,
			 void *out_data, size_t out_data_size,
			 struct xrp_buffer_group *buffer_group,
			 struct xrp_event **evt,
			 enum xrp_status *status)
{
	struct xrp_device *device = queue->device;
	size_t n_buffers;
	size_t i;
	struct xrp_request *rq = malloc(sizeof(*rq));
	struct xrp_dsp_cmd *dsp_cmd = &rq->dsp_cmd;
	void *in_data_ptr;

	rq->in_data_size = in_data_size;
	rq->out_data = out_data;
	rq->out_data_size = out_data_size;
	rq->buffer_group = buffer_group;
	if (buffer_group)
		xrp_retain_buffer_group(buffer_group, NULL);

	if (in_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		long rc = xrp_allocate(device->impl.description->shared_pool,
				       in_data_size,
				       0x10, &rq->in_data_allocation);
		if (rc < 0) {
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		dsp_cmd->in_data_addr = rq->in_data_allocation->start;
		in_data_ptr = p2v(rq->in_data_allocation->start);
	} else {
		in_data_ptr = &dsp_cmd->in_data;
	}
	dsp_cmd->in_data_size = in_data_size;
	memcpy(in_data_ptr, in_data, in_data_size);

	if (out_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		long rc = xrp_allocate(device->impl.description->shared_pool,
				       out_data_size,
				       0x10, &rq->out_data_allocation);
		if (rc < 0) {
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		dsp_cmd->out_data_addr = rq->out_data_allocation->start;
		rq->out_data_ptr = p2v(rq->out_data_allocation->start);
	} else {
		rq->out_data_ptr = &dsp_cmd->out_data;
	}
	dsp_cmd->out_data_size = out_data_size;

	if (buffer_group)
		xrp_mutex_lock(&buffer_group->mutex);

	n_buffers = buffer_group ? buffer_group->n_buffers : 0;
	if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
		long rc = xrp_allocate(device->impl.description->shared_pool,
				       n_buffers * sizeof(struct xrp_dsp_buffer),
				       0x10, &rq->buffer_allocation);
		if (rc < 0) {
			xrp_mutex_unlock(&buffer_group->mutex);
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		dsp_cmd->buffer_addr = rq->buffer_allocation->start;
		rq->buffer_ptr = p2v(rq->buffer_allocation->start);
	} else {
		rq->buffer_ptr = dsp_cmd->buffer_data;
	}
	dsp_cmd->buffer_size = n_buffers * sizeof(struct xrp_dsp_buffer);

	rq->n_buffers = n_buffers;
	rq->user_buffer_allocation = malloc(n_buffers * sizeof(void *));
	for (i = 0; i < n_buffers; ++i) {
		phys_addr_t addr;

		if (buffer_group->buffer[i].buffer->map_count > 0) {
			xrp_mutex_unlock(&buffer_group->mutex);
			set_status(status, XRP_STATUS_FAILURE);
			return;

		}
		if (buffer_group->buffer[i].buffer->type == XRP_BUFFER_TYPE_DEVICE) {
			addr = buffer_group->buffer[i].buffer->impl.xrp_allocation->start;
		} else {
			long rc = xrp_allocate(device->impl.description->shared_pool,
					       buffer_group->buffer[i].buffer->size,
					       0x10, rq->user_buffer_allocation + i);

			if (rc < 0) {
				set_status(status, XRP_STATUS_FAILURE);
				return;
			}
			addr = rq->user_buffer_allocation[i]->start;
			memcpy(p2v(addr), buffer_group->buffer[i].buffer->ptr,
			       buffer_group->buffer[i].buffer->size);
		}
		rq->buffer_ptr[i] = (struct xrp_dsp_buffer){
			.flags = buffer_group->buffer[i].access_flags,
			.size = buffer_group->buffer[i].buffer->size,
			.addr = addr,
		};
	}

	if (buffer_group)
		xrp_mutex_unlock(&buffer_group->mutex);

	if (evt) {
		struct xrp_event *event = xrp_event_create();

		if (!event) {
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		xrp_retain_queue(queue, NULL);
		event->queue = queue;
		*evt = event;
		xrp_retain_event(event, NULL);
		rq->event = event;
	} else {
		rq->event = NULL;
	}
	dsp_cmd->flags = (queue->use_nsid ? XRP_DSP_CMD_FLAG_REQUEST_NSID : 0);
	if (queue->use_nsid) {
		memcpy(dsp_cmd->nsid, queue->nsid, sizeof(dsp_cmd->nsid));
	}
	xrp_queue_push(&device->impl.queue, &rq->q);
	set_status(status, XRP_STATUS_SUCCESS);
}
