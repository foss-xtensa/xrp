/*
 * Copyright (c) 2016 - 2017 Cadence Design Systems Inc.
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
#include <xtensa/xtruntime.h>

#include "xrp_api.h"
#include "xrp_debug.h"
#include "xrp_dsp_hw.h"
#include "xrp_dsp_sync.h"
#include "xrp_dsp_user.h"
#include "xrp_ns.h"
#include "xrp_types.h"
#include "xrp_kernel_dsp_interface.h"

extern char xrp_dsp_comm_base_magic[] __attribute__((weak));
void *xrp_dsp_comm_base = &xrp_dsp_comm_base_magic;

static int manage_cache;

#define MAX_STACK_BUFFERS 16
#define MAX_TLV_LENGTH 0x10000

/* DSP side XRP API implementation */

struct xrp_refcounted {
	unsigned long count;
};

struct xrp_device {
	struct xrp_refcounted ref;
	void *dsp_cmd;
};

struct xrp_buffer {
	struct xrp_refcounted ref;
	void *ptr;
	size_t size;
	unsigned long map_count;
	enum xrp_access_flags allowed_access;
	enum xrp_access_flags map_flags;
};

struct xrp_buffer_group {
	struct xrp_refcounted ref;
	size_t n_buffers;
	struct xrp_buffer *buffer;
};

static struct xrp_cmd_ns_map ns_map;
static size_t dsp_hw_queue_entry_size = XRP_DSP_CMD_STRIDE;
static struct xrp_device dsp_device0;
static int n_dsp_devices;
static struct xrp_device **dsp_device;

void xrp_device_enable_cache(struct xrp_device *device, int enable)
{
	(void)device;
	manage_cache = enable;
}

static inline void dcache_region_invalidate(void *p, size_t sz)
{
	if (manage_cache)
		xthal_dcache_region_invalidate(p, sz);
}

static inline void dcache_region_writeback(void *p, size_t sz)
{
	if (manage_cache)
		xthal_dcache_region_writeback(p, sz);
}

static inline void set_status(enum xrp_status *status, enum xrp_status v)
{
	if (status)
		*status = v;
}

static void retain_refcounted(struct xrp_refcounted *ref)
{
	if (ref) {
		++ref->count;
	}
}

static void release_refcounted(struct xrp_refcounted *ref)
{
	if (ref) {
		--ref->count;
	}
}

struct xrp_device *xrp_open_device(int idx, enum xrp_status *status)
{
	if (idx == 0) {
		dsp_device0.dsp_cmd = xrp_dsp_comm_base;
		set_status(status, XRP_STATUS_SUCCESS);
		return &dsp_device0;
	} else if (idx < n_dsp_devices) {
		xrp_retain_device(dsp_device[idx]);
		set_status(status, XRP_STATUS_SUCCESS);
		return dsp_device[idx];
	} else {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}
}

void xrp_retain_device(struct xrp_device *device)
{
	retain_refcounted(&device->ref);
}

void xrp_release_device(struct xrp_device *device)
{
	release_refcounted(&device->ref);
}

struct xrp_buffer *xrp_create_buffer(struct xrp_device *device,
				     size_t size, void *host_ptr,
				     enum xrp_status *status)
{
	(void)device;
	(void)size;
	(void)host_ptr;
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}

void xrp_retain_buffer(struct xrp_buffer *buffer)
{
	retain_refcounted(&buffer->ref);
}

void xrp_release_buffer(struct xrp_buffer *buffer)
{
	release_refcounted(&buffer->ref);
}

void *xrp_map_buffer(struct xrp_buffer *buffer, size_t offset, size_t size,
		     enum xrp_access_flags map_flags, enum xrp_status *status)
{
	if (offset <= buffer->size &&
	    size <= buffer->size - offset &&
	    (buffer->allowed_access & map_flags) == map_flags) {
		retain_refcounted(&buffer->ref);
		++buffer->map_count;
		buffer->map_flags |= map_flags;
		set_status(status, XRP_STATUS_SUCCESS);
		return buffer->ptr + offset;
	}
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}

void xrp_unmap_buffer(struct xrp_buffer *buffer, void *p,
		      enum xrp_status *status)
{
	if (p >= buffer->ptr && (size_t)(p - buffer->ptr) <= buffer->size) {
		--buffer->map_count;
		release_refcounted(&buffer->ref);
		set_status(status, XRP_STATUS_SUCCESS);
	} else {
		set_status(status, XRP_STATUS_FAILURE);
	}
}

void xrp_buffer_get_info(struct xrp_buffer *buffer, enum xrp_buffer_info info,
			 void *out, size_t out_sz, enum xrp_status *status)
{
	enum xrp_status s = XRP_STATUS_FAILURE;
	size_t sz;
	void *ptr;

	switch (info) {
	case XRP_BUFFER_SIZE_SIZE_T:
		sz = sizeof(buffer->size);
		ptr = &buffer->size;
		break;

	case XRP_BUFFER_HOST_POINTER_PTR:
		sz = sizeof(void *);
		ptr = &buffer->ptr;
		break;

	default:
		goto out;
	}

	if (sz == out_sz) {
		memcpy(out, ptr, sz);
		s = XRP_STATUS_SUCCESS;
	}
out:
	set_status(status, s);
}

struct xrp_buffer_group *xrp_create_buffer_group(enum xrp_status *status)
{
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}

void xrp_retain_buffer_group(struct xrp_buffer_group *group)
{
	retain_refcounted(&group->ref);
}

void xrp_release_buffer_group(struct xrp_buffer_group *group)
{
	release_refcounted(&group->ref);
}

size_t xrp_add_buffer_to_group(struct xrp_buffer_group *group,
			       struct xrp_buffer *buffer,
			       enum xrp_access_flags access_flags,
			       enum xrp_status *status)
{
	(void)group;
	(void)buffer;
	(void)access_flags;
	set_status(status, XRP_STATUS_FAILURE);
	return -1;
}

struct xrp_buffer *xrp_get_buffer_from_group(struct xrp_buffer_group *group,
					     size_t idx,
					     enum xrp_status *status)
{
	if (idx < group->n_buffers) {
		set_status(status, XRP_STATUS_SUCCESS);
		xrp_retain_buffer(group->buffer + idx);
		return group->buffer + idx;
	}
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}

void xrp_buffer_group_get_info(struct xrp_buffer_group *group,
			       enum xrp_buffer_group_info info, size_t idx,
			       void *out, size_t out_sz,
			       enum xrp_status *status)
{
	enum xrp_status s = XRP_STATUS_FAILURE;
	size_t sz;
	void *ptr;

	switch (info) {
	case XRP_BUFFER_GROUP_BUFFER_FLAGS_ENUM:
		if (idx >= group->n_buffers)
			goto out;
		sz = sizeof(group->buffer[idx].allowed_access);
		ptr = &group->buffer[idx].allowed_access;
		break;

        case XRP_BUFFER_GROUP_SIZE_SIZE_T:
                sz = sizeof(group->n_buffers);
                ptr = &group->n_buffers;
                break;

	default:
		goto out;
	}

	if (sz == out_sz) {
		memcpy(out, ptr, sz);
		s = XRP_STATUS_SUCCESS;
	}
out:
	set_status(status, s);
}

/* DSP side request handling */

static int update_hw_queues(uint32_t queue_priority[], int n)
{
	if (xrp_user_create_queues) {
		struct xrp_device **new_device = malloc(n * sizeof(void *));
		struct xrp_device **old_device = dsp_device;
		int n_old = n_dsp_devices;
		int i;

		if (!new_device) {
			pr_debug("%s: device array allocation failed\n",
				 __func__);
			return 0;
		}
		for (i = 1; i < n; ++i) {
			new_device[i] = calloc(1, sizeof(struct xrp_device));
			if (!new_device[i]) {
				pr_debug("%s: device allocation failed\n",
					 __func__);
				while (--i)
					xrp_release_device(new_device[i]);
				free(new_device);

				return 0;
			}
			new_device[i]->dsp_cmd = xrp_dsp_comm_base +
				i * dsp_hw_queue_entry_size;
			xrp_retain_device(new_device[i]);
		}
		dsp_device = new_device;
		n_dsp_devices = n;

		for (i = 1; i < n_old; ++i)
			xrp_release_device(old_device[i]);
		free(old_device);

		return xrp_user_create_queues(n, queue_priority) ==
			XRP_STATUS_SUCCESS;
	} else {
		return 0;
	}
}

static void process_sync_data(struct xrp_device *device,
			      struct xrp_dsp_tlv *data)
{
	(void)device;

	for (;; data = (void *)(data->value + ((data->length + 3) / 4))) {
		dcache_region_invalidate(data, sizeof(*data));

		if (data->length >= MAX_TLV_LENGTH) {
			pr_debug("%s: suspicious length, data = %p, length = %d\n",
				 __func__, data, (unsigned)data->length);
			break;
		}
		dcache_region_invalidate(data->value, data->length);

		switch (data->type & XRP_DSP_SYNC_TYPE_MASK) {
		case XRP_DSP_SYNC_TYPE_LAST:
			return;

		case XRP_DSP_SYNC_TYPE_HW_SPEC_DATA:
			if (xrp_hw_set_sync_data)
				xrp_hw_set_sync_data(data->value);
			data->type |= XRP_DSP_SYNC_TYPE_ACCEPT;
			break;

		case XRP_DSP_SYNC_TYPE_HW_QUEUES:
			if (update_hw_queues(data->value,
					     data->length / 4))
				data->type |= XRP_DSP_SYNC_TYPE_ACCEPT;
			break;

		default:
			pr_debug("%s, unrecognized TLV: type = 0x%08x, length = %d\n",
				 __func__, data->type, data->length);
			continue;
		}
		dcache_region_writeback(data, sizeof(data) + data->length);
	}
}

static void do_handshake(struct xrp_device *device)
{
	struct xrp_dsp_sync_v2 *shared_sync = device->dsp_cmd;
	uint32_t v;

	pr_debug("%s, shared_sync = %p\n", __func__, shared_sync);

	while (xrp_l32ai(&shared_sync->sync) != XRP_DSP_SYNC_START) {
		dcache_region_invalidate(&shared_sync->sync,
					 sizeof(shared_sync->sync));
	}

	xrp_s32ri(XRP_DSP_SYNC_DSP_READY_V2, &shared_sync->sync);
	dcache_region_writeback(&shared_sync->sync,
				sizeof(shared_sync->sync));

	for (;;) {
		dcache_region_invalidate(&shared_sync->sync,
					 sizeof(shared_sync->sync));
		v = xrp_l32ai(&shared_sync->sync);
		if (v == XRP_DSP_SYNC_HOST_TO_DSP)
			break;
		if (v != XRP_DSP_SYNC_DSP_READY_V2)
			return;
	}

	process_sync_data(device, shared_sync->hw_sync_data);

	xrp_s32ri(XRP_DSP_SYNC_DSP_TO_HOST, &shared_sync->sync);
	dcache_region_writeback(&shared_sync->sync,
				sizeof(shared_sync->sync));

	xrp_hw_wait_device_irq();

	xrp_hw_send_host_irq();

	pr_debug("%s: done\n", __func__);
}

static inline int xrp_request_valid(struct xrp_dsp_cmd *dsp_cmd,
				    uint32_t *pflags)
{
	uint32_t flags = xrp_l32ai(&dsp_cmd->flags);

	*pflags = flags;
	return (flags & (XRP_DSP_CMD_FLAG_REQUEST_VALID |
			 XRP_DSP_CMD_FLAG_RESPONSE_VALID)) ==
		XRP_DSP_CMD_FLAG_REQUEST_VALID;

}

static void complete_request(struct xrp_dsp_cmd *dsp_cmd, uint32_t flags)
{
	flags |= XRP_DSP_CMD_FLAG_RESPONSE_VALID;

	dcache_region_writeback(dsp_cmd,
				sizeof(*dsp_cmd));
	xrp_s32ri(flags, &dsp_cmd->flags);
	dcache_region_writeback(&dsp_cmd->flags,
				sizeof(dsp_cmd->flags));
	xrp_hw_send_host_irq();
}

static enum xrp_access_flags dsp_buffer_allowed_access(__u32 flags)
{
	return flags == XRP_DSP_BUFFER_FLAG_READ ?
		XRP_READ : XRP_READ_WRITE;
}

void xrp_run_command(const void *in_data, size_t in_data_size,
		     void *out_data, size_t out_data_size,
		     struct xrp_buffer_group *buffer_group,
		     enum xrp_status *status) __attribute__((weak));

void xrp_run_command(const void *in_data, size_t in_data_size,
		     void *out_data, size_t out_data_size,
		     struct xrp_buffer_group *buffer_group,
		     enum xrp_status *status)
{
	(void)in_data;
	(void)in_data_size;
	(void)out_data;
	(void)out_data_size;
	(void)buffer_group;
	*status = XRP_STATUS_FAILURE;
}

static inline enum xrp_status
xrp_run_command_handler(void *handler_context,
			const void *in_data, size_t in_data_size,
			void *out_data, size_t out_data_size,
			struct xrp_buffer_group *buffer_group)
{
	enum xrp_status status = XRP_STATUS_FAILURE;

	(void)handler_context;
	xrp_run_command(in_data, in_data_size,
			out_data, out_data_size,
			buffer_group, &status);
	return status;
}

static enum xrp_status process_command(struct xrp_device *device,
				       uint32_t flags)
{
	enum xrp_status status;
	struct xrp_dsp_cmd *dsp_cmd = device->dsp_cmd;
	size_t n_buffers = dsp_cmd->buffer_size / sizeof(struct xrp_dsp_buffer);
	struct xrp_dsp_buffer *dsp_buffer;
	struct xrp_buffer_group buffer_group;
	struct xrp_buffer sbuffer[n_buffers <= MAX_STACK_BUFFERS ? n_buffers : 1];
	struct xrp_buffer *buffer = sbuffer;
	xrp_command_handler *command_handler = xrp_run_command_handler;
	void *handler_context = NULL;
	size_t i;

	if (dsp_cmd->flags & XRP_DSP_CMD_FLAG_REQUEST_NSID) {
		struct xrp_cmd_ns *cmd_ns = xrp_find_cmd_ns(&ns_map,
							    dsp_cmd->nsid);
		if (xrp_cmd_ns_match(dsp_cmd->nsid, cmd_ns)) {
			command_handler = cmd_ns->handler;
			handler_context = cmd_ns->handler_context;
		} else {
			flags |= XRP_DSP_CMD_FLAG_RESPONSE_DELIVERY_FAIL;
			status = XRP_STATUS_FAILURE;
			goto out;
		}
	}

	if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
		dsp_buffer = (void *)dsp_cmd->buffer_addr;
		dcache_region_invalidate(dsp_buffer,
					 n_buffers * sizeof(*dsp_buffer));

	} else {
		dsp_buffer = (void *)&dsp_cmd->buffer_data;
	}
	if (dsp_cmd->in_data_size > sizeof(dsp_cmd->in_data)) {
		dcache_region_invalidate((void *)dsp_cmd->in_data_addr,
					 dsp_cmd->in_data_size);
	}
	if (n_buffers > MAX_STACK_BUFFERS) {
		buffer = malloc(n_buffers * sizeof(*buffer));
		if (!buffer) {
			status = XRP_STATUS_FAILURE;
			goto out;
		}
	}

	/* Create buffers from incoming buffer data, put them to group.
	 * Passed flags add some restrictions to possible buffer mapping
	 * modes:
	 * R only allows R
	 * W and RW allow R, W or RW
	 * (actually W only allows W and RW, but that's hard to express and
	 * is not particularly useful)
	 */
	for (i = 0; i < n_buffers; ++i) {
		buffer[i] = (struct xrp_buffer){
			.allowed_access =
				dsp_buffer_allowed_access(dsp_buffer[i].flags),
			.ptr = (void *)dsp_buffer[i].addr,
			.size = dsp_buffer[i].size,
		};
		if (buffer[i].allowed_access & XRP_READ) {
			dcache_region_invalidate(buffer[i].ptr,
						 buffer[i].size);
		}
	}

	buffer_group = (struct xrp_buffer_group){
		.n_buffers = n_buffers,
		.buffer = buffer,
	};

	status = command_handler(handler_context,
				 dsp_cmd->in_data_size > sizeof(dsp_cmd->in_data) ?
				 (void *)dsp_cmd->in_data_addr : dsp_cmd->in_data,
				 dsp_cmd->in_data_size,
				 dsp_cmd->out_data_size > sizeof(dsp_cmd->out_data) ?
				 (void *)dsp_cmd->out_data_addr : dsp_cmd->out_data,
				 dsp_cmd->out_data_size,
				 &buffer_group);

	if (status != XRP_STATUS_SUCCESS)
		flags |= XRP_DSP_CMD_FLAG_RESPONSE_DELIVERY_FAIL;

	/*
	 * update flags in the buffer data: what access actually took place,
	 * to update caches on the host side.
	 */
	for (i = 0; i < n_buffers; ++i) {
		__u32 flags = 0;

		if (buffer[i].map_flags & XRP_READ)
			flags |= XRP_DSP_BUFFER_FLAG_READ;
		if (buffer[i].map_flags & XRP_WRITE)
			flags |= XRP_DSP_BUFFER_FLAG_WRITE;

		pr_debug("%s: dsp_buffer[%d].flags = %d\n", __func__, i, flags);
		dsp_buffer[i].flags = flags;

		if (buffer[i].ref.count) {
			pr_debug("%s: refcount leak on buffer %d\n",
				__func__, i);
		}
		if (buffer[i].map_count) {
			pr_debug("%s: map_count leak on buffer %d\n",
				__func__, i);
		}
		if (buffer[i].map_flags & XRP_WRITE) {
			dcache_region_writeback(buffer[i].ptr,
						buffer[i].size);
		}
	}
	if (buffer_group.ref.count) {
		pr_debug("%s: refcount leak on buffer group\n", __func__);
	}
	if (dsp_cmd->out_data_size > sizeof(dsp_cmd->out_data)) {
		dcache_region_writeback((void *)dsp_cmd->out_data_addr,
					dsp_cmd->out_data_size);
	}
	if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
		dcache_region_writeback(dsp_buffer,
					n_buffers * sizeof(*dsp_buffer));
	}
	if (n_buffers > MAX_STACK_BUFFERS) {
		free(buffer);
	}
out:
	complete_request(dsp_cmd, flags);
	return status;
}

void xrp_device_register_namespace(struct xrp_device *device,
				   const void *nsid,
				   xrp_command_handler *handler,
				   void *handler_context,
				   enum xrp_status *status)
{
	(void)device;
	if (xrp_register_namespace(&ns_map,
				   nsid, handler, handler_context))
		set_status(status, XRP_STATUS_SUCCESS);
	else
		set_status(status, XRP_STATUS_FAILURE);
}

void xrp_device_unregister_namespace(struct xrp_device *device,
				     const void *nsid,
				     enum xrp_status *status)
{
	(void)device;
	if (xrp_unregister_namespace(&ns_map, nsid))
		set_status(status, XRP_STATUS_SUCCESS);
	else
		set_status(status, XRP_STATUS_FAILURE);
}

enum xrp_status xrp_device_poll(struct xrp_device *device)
{
	uint32_t flags;

	dcache_region_invalidate(device->dsp_cmd,
				 sizeof(struct xrp_dsp_cmd));
	if (xrp_request_valid(device->dsp_cmd, &flags))
		return XRP_STATUS_SUCCESS;
	else
		return XRP_STATUS_PENDING;
}

enum xrp_status xrp_device_dispatch(struct xrp_device *device)
{
	uint32_t flags;
	enum xrp_status status;

	dcache_region_invalidate(device->dsp_cmd,
				 sizeof(struct xrp_dsp_cmd));
	if (!xrp_request_valid(device->dsp_cmd, &flags))
		return XRP_STATUS_PENDING;

	if (flags == XRP_DSP_SYNC_START) {
		do_handshake(device);
		status = XRP_STATUS_SUCCESS;
	} else {
		status = process_command(device, flags);
	}
	return status;
}
