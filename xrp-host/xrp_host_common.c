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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "xrp_api.h"
#include "xrp_host_common.h"


/* Device API. */

void xrp_retain_device(struct xrp_device *device)
{
	retain_refcounted(device);
}

void xrp_release_device(struct xrp_device *device)
{
	if (last_release_refcounted(device)) {
		xrp_impl_release_device(device);
		free(device);
	}
}


/* Buffer API. */

struct xrp_buffer *xrp_create_buffer(struct xrp_device *device,
				     size_t size, void *host_ptr,
				     enum xrp_status *status)
{
	struct xrp_buffer *buf;

	if (!host_ptr && !device) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	buf = alloc_refcounted(sizeof(*buf));

	if (!buf) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	if (!host_ptr) {
		enum xrp_status s;

		buf->type = XRP_BUFFER_TYPE_DEVICE;
		xrp_impl_create_device_buffer(device, buf, size, &s);
		if (s != XRP_STATUS_SUCCESS) {
			free(buf);
			buf = NULL;
		}
		set_status(status, s);
	} else {
		buf->type = XRP_BUFFER_TYPE_HOST;
		buf->ptr = host_ptr;
		buf->size = size;
		set_status(status, XRP_STATUS_SUCCESS);
	}
	return buf;
}

void xrp_retain_buffer(struct xrp_buffer *buffer)
{
	retain_refcounted(buffer);
}

void xrp_release_buffer(struct xrp_buffer *buffer)
{
	if (last_release_refcounted(buffer)) {
		if (buffer->type == XRP_BUFFER_TYPE_DEVICE)
			xrp_impl_release_device_buffer(buffer);
		free(buffer);
	}
}

void *xrp_map_buffer(struct xrp_buffer *buffer, size_t offset, size_t size,
		     enum xrp_access_flags map_flags, enum xrp_status *status)
{
	if (offset <= buffer->size &&
	    size <= buffer->size - offset) {
		retain_refcounted(buffer);
		(void)++buffer->map_count;
		buffer->map_flags |= map_flags;
		set_status(status, XRP_STATUS_SUCCESS);
		return (char *)buffer->ptr + offset;
	}
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}

void xrp_unmap_buffer(struct xrp_buffer *buffer, void *p,
		      enum xrp_status *status)
{
	if (p >= buffer->ptr &&
	    (size_t)((char *)p - (char *)buffer->ptr) <= buffer->size) {
		(void)--buffer->map_count;
		xrp_release_buffer(buffer);
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
		if (buffer->type != XRP_BUFFER_TYPE_HOST) {
			static void *p = NULL;
			ptr = &p;
		} else {
			ptr = &buffer->ptr;
		}
		sz = sizeof(void *);
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


/* Buffer group API. */

struct xrp_buffer_group *xrp_create_buffer_group(enum xrp_status *status)
{
	struct xrp_buffer_group *group = alloc_refcounted(sizeof(*group));

	if (group) {
		xrp_mutex_init(&group->mutex);
		set_status(status, XRP_STATUS_SUCCESS);
	} else {
		set_status(status, XRP_STATUS_FAILURE);
	}

	return group;
}

void xrp_retain_buffer_group(struct xrp_buffer_group *group)
{
	retain_refcounted(group);
}

void xrp_release_buffer_group(struct xrp_buffer_group *group)
{
	if (last_release_refcounted(group)) {
		size_t i;

		xrp_mutex_lock(&group->mutex);
		for (i = 0; i < group->n_buffers; ++i)
			xrp_release_buffer(group->buffer[i].buffer);
		xrp_mutex_unlock(&group->mutex);
		xrp_mutex_destroy(&group->mutex);
		free(group->buffer);
		free(group);
	}
}

size_t xrp_add_buffer_to_group(struct xrp_buffer_group *group,
			       struct xrp_buffer *buffer,
			       enum xrp_access_flags access_flags,
			       enum xrp_status *status)
{
	size_t n_buffers;

	xrp_mutex_lock(&group->mutex);
	if (group->n_buffers == group->capacity) {
		struct xrp_buffer_group_record *r =
			realloc(group->buffer,
				sizeof(struct xrp_buffer_group_record) *
				((group->capacity + 2) * 2));

		if (r == NULL) {
			xrp_mutex_unlock(&group->mutex);
			set_status(status, XRP_STATUS_FAILURE);
			return -1;
		}
		group->buffer = r;
		group->capacity = (group->capacity + 2) * 2;
	}

	xrp_retain_buffer(buffer);
	group->buffer[group->n_buffers].buffer = buffer;
	group->buffer[group->n_buffers].access_flags = access_flags;
	n_buffers = group->n_buffers++;
	xrp_mutex_unlock(&group->mutex);
	set_status(status, XRP_STATUS_SUCCESS);
	return n_buffers;
}

void xrp_set_buffer_in_group(struct xrp_buffer_group *group,
			     size_t index,
			     struct xrp_buffer *buffer,
			     enum xrp_access_flags access_flags,
			     enum xrp_status *status)
{
	struct xrp_buffer *old_buffer;

	xrp_retain_buffer(buffer);

	xrp_mutex_lock(&group->mutex);
	if (index < group->n_buffers) {
		old_buffer = group->buffer[index].buffer;
		group->buffer[index].buffer = buffer;
		group->buffer[index].access_flags = access_flags;
		set_status(status, XRP_STATUS_SUCCESS);
	} else {
		old_buffer = buffer;
		set_status(status, XRP_STATUS_FAILURE);
	}
	xrp_mutex_unlock(&group->mutex);
	xrp_release_buffer(old_buffer);
}

struct xrp_buffer *xrp_get_buffer_from_group(struct xrp_buffer_group *group,
					     size_t idx,
					     enum xrp_status *status)
{
	struct xrp_buffer *buffer = NULL;

	xrp_mutex_lock(&group->mutex);
	if (idx < group->n_buffers) {
		buffer = group->buffer[idx].buffer;
		xrp_retain_buffer(buffer);
		set_status(status, XRP_STATUS_SUCCESS);
	} else {
		set_status(status, XRP_STATUS_FAILURE);
	}
	xrp_mutex_unlock(&group->mutex);
	return buffer;
}

void xrp_buffer_group_get_info(struct xrp_buffer_group *group,
			       enum xrp_buffer_group_info info, size_t idx,
			       void *out, size_t out_sz,
			       enum xrp_status *status)
{
	enum xrp_status s = XRP_STATUS_FAILURE;
	size_t sz;
	void *ptr;

	xrp_mutex_lock(&group->mutex);
	switch (info) {
	case XRP_BUFFER_GROUP_BUFFER_FLAGS_ENUM:
		if (idx >= group->n_buffers)
			goto out;
		sz = sizeof(group->buffer[idx].access_flags);
		ptr = &group->buffer[idx].access_flags;
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
	xrp_mutex_unlock(&group->mutex);
	set_status(status, s);
}


/* Queue API. */

struct xrp_queue *xrp_create_queue(struct xrp_device *device,
				   enum xrp_status *status)
{
	return xrp_create_ns_queue(device, NULL, status);
}

struct xrp_queue *xrp_create_ns_queue(struct xrp_device *device,
				      const void *nsid,
				      enum xrp_status *status)
{
	return xrp_create_nsp_queue(device, nsid, 0, status);
}

struct xrp_queue *xrp_create_nsp_queue(struct xrp_device *device,
				       const void *nsid,
				       int priority,
				       enum xrp_status *status)
{
	struct xrp_queue *queue;

	xrp_retain_device(device);
	queue = alloc_refcounted(sizeof(*queue));

	if (!queue) {
		xrp_release_device(device);
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	queue->device = device;
	if (nsid) {
		queue->use_nsid = 1;
		memcpy(queue->nsid, nsid, XRP_NAMESPACE_ID_SIZE);
	}
	queue->priority = priority;

	xrp_impl_create_queue(queue, status);

	return queue;
}

void xrp_retain_queue(struct xrp_queue *queue)
{
	retain_refcounted(queue);
}

void xrp_release_queue(struct xrp_queue *queue)
{
	if (last_release_refcounted(queue)) {
		xrp_impl_release_queue(queue);
		xrp_release_device(queue->device);
		free(queue);
	}
}


/* Event API. */

void xrp_retain_event(struct xrp_event *event)
{
	retain_refcounted(event);
}

void xrp_release_event(struct xrp_event *event)
{
	if (last_release_refcounted(event)) {
		xrp_impl_release_event(event);
		xrp_release_queue(event->queue);
		free(event);
	}
}

void xrp_event_status(struct xrp_event *event, enum xrp_status *status)
{
	set_status(status, event->status);
}

/* Communication API */

void xrp_run_command_sync(struct xrp_queue *queue,
			  const void *in_data, size_t in_data_size,
			  void *out_data, size_t out_data_size,
			  struct xrp_buffer_group *buffer_group,
			  enum xrp_status *status)
{
	struct xrp_event *evt;
	enum xrp_status s;

	xrp_enqueue_command(queue, in_data, in_data_size,
			    out_data, out_data_size,
			    buffer_group, &evt, &s);
	if (s != XRP_STATUS_SUCCESS) {
		set_status(status, s);
		return;
	}
	xrp_wait(evt, NULL);
	xrp_event_status(evt, status);
	xrp_release_event(evt);
}
