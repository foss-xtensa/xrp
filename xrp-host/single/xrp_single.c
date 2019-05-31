/*
 * Copyright (c) 2018 Cadence Design Systems Inc.
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
#include <unistd.h>

#include "xrp_host_common.h"
#include "xrp_host_impl.h"
#include "xrp_ns.h"

struct xrp_device_description {
	struct xrp_cmd_ns_map ns_map;
};

static struct xrp_device_description xrp_device_description[1];

struct xrp_request {
	struct xrp_queue_item q;

	struct xrp_queue *queue;
	void *in_data;
	void *out_data;
	size_t in_data_size;
	size_t out_data_size;
	struct xrp_buffer_group *buffer_group;
	struct xrp_event *event;
};

/* Device API. */

static void xrp_request_process(struct xrp_queue_item *rq,
				void *context);

struct xrp_device *xrp_open_device(int idx, enum xrp_status *status)
{
	struct xrp_device *device;

	if (idx < 0 || idx > 1) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}
	device = alloc_refcounted(sizeof(*device));
	if (!device) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}
	device->impl.description = xrp_device_description + idx;
	set_status(status, XRP_STATUS_SUCCESS);
	return device;
}

void xrp_impl_release_device(struct xrp_device *device)
{
	(void)device;
}


/* Buffer API. */

void xrp_impl_create_device_buffer(struct xrp_device *device,
				   struct xrp_buffer *buffer,
				   size_t size,
				   enum xrp_status *status)
{
	(void)device;
	buffer->ptr = malloc(size);
	buffer->size = size;
	if (buffer->ptr)
		set_status(status, XRP_STATUS_SUCCESS);
	else
		set_status(status, XRP_STATUS_FAILURE);
}

void xrp_impl_release_device_buffer(struct xrp_buffer *buffer)
{
	free(buffer->ptr);
}

/* Queue API. */

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

static void _xrp_run_command(struct xrp_queue *queue,
			     const void *in_data, size_t in_data_size,
			     void *out_data, size_t out_data_size,
			     struct xrp_buffer_group *buffer_group,
			     enum xrp_status *status)
{
	enum xrp_status s;
	xrp_command_handler *command_handler = xrp_run_command_handler;
	void *handler_context = NULL;

	if (queue->use_nsid) {
		struct xrp_cmd_ns *cmd_ns;

		cmd_ns = xrp_find_cmd_ns(&queue->device->impl.description->ns_map,
					 queue->nsid);

		if (xrp_cmd_ns_match(queue->nsid, cmd_ns)) {
			command_handler = cmd_ns->handler;
			handler_context = cmd_ns->handler_context;
		} else {
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
	}
	s = command_handler(handler_context,
			    in_data, in_data_size,
			    out_data, out_data_size,
			    buffer_group);

	set_status(status, s);
}

static void xrp_request_process(struct xrp_queue_item *q,
				void *context)
{
	enum xrp_status status;
	struct xrp_request *rq = (struct xrp_request *)q;

	(void)context;
	_xrp_run_command(rq->queue,
			 rq->in_data, rq->in_data_size,
			 rq->out_data, rq->out_data_size,
			 rq->buffer_group,
			 &status);

	xrp_release_queue(rq->queue);

	if (rq->buffer_group)
		xrp_release_buffer_group(rq->buffer_group);

	if (rq->event) {
		xrp_impl_broadcast_event(rq->event, status);
		xrp_release_event(rq->event);
	}
	free(rq->in_data);
	free(rq);
}

void xrp_impl_create_queue(struct xrp_queue *queue,
			   enum xrp_status *status)
{
	xrp_queue_init(&queue->impl.queue,
		       queue->priority, NULL,
		       xrp_request_process);
	set_status(status, XRP_STATUS_SUCCESS);
}

void xrp_impl_release_queue(struct xrp_queue *queue)
{
	xrp_queue_destroy(&queue->impl.queue);
}

/* Communication API */

void xrp_enqueue_command(struct xrp_queue *queue,
			 const void *in_data, size_t in_data_size,
			 void *out_data, size_t out_data_size,
			 struct xrp_buffer_group *buffer_group,
			 struct xrp_event **evt,
			 enum xrp_status *status)
{
	struct xrp_request *rq;
	void *in_data_copy;

	rq = malloc(sizeof(*rq));
	in_data_copy = malloc(in_data_size);
	if (buffer_group)
		xrp_retain_buffer_group(buffer_group);
	else
		buffer_group = xrp_create_buffer_group(status);

	if (!rq || (in_data_size && !in_data_copy) || !buffer_group) {
		free(in_data_copy);
		free(rq);
		if (buffer_group)
			xrp_release_buffer_group(buffer_group);
		set_status(status, XRP_STATUS_FAILURE);
		return;
	}

	memcpy(in_data_copy, in_data, in_data_size);
	xrp_retain_queue(queue);
	rq->queue = queue;
	rq->in_data = in_data_copy;
	rq->in_data_size = in_data_size;
	rq->out_data = out_data;
	rq->out_data_size = out_data_size;
	rq->buffer_group = buffer_group;

	if (evt) {
		struct xrp_event *event = xrp_event_create();

		if (!event) {
			free(rq->in_data);
			free(rq);
			xrp_release_buffer_group(buffer_group);
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		xrp_retain_queue(queue);
		event->queue = queue;
		*evt = event;
		xrp_retain_event(event);
		rq->event = event;
	} else {
		rq->event = NULL;
	}

	set_status(status, XRP_STATUS_SUCCESS);
	xrp_queue_push(&queue->impl.queue, &rq->q);
}

/* Namespace DSP side API. */

void xrp_device_register_namespace(struct xrp_device *device,
				   const void *nsid,
				   xrp_command_handler *handler,
				   void *handler_context,
				   enum xrp_status *status)
{
	if (xrp_register_namespace(&device->impl.description->ns_map,
				   nsid, handler, handler_context))
		set_status(status, XRP_STATUS_SUCCESS);
	else
		set_status(status, XRP_STATUS_FAILURE);
}

void xrp_device_unregister_namespace(struct xrp_device *device,
				     const void *nsid,
				     enum xrp_status *status)
{
	if (xrp_unregister_namespace(&device->impl.description->ns_map, nsid))
		set_status(status, XRP_STATUS_SUCCESS);
	else
		set_status(status, XRP_STATUS_FAILURE);
}
