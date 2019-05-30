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

#include <stdio.h>
#include "xrp_host_common.h"
#include "xrp_sync_queue.h"

void xrp_queue_init(struct xrp_request_queue *queue, int priority,
		    void *context,
		    void (*fn)(struct xrp_queue_item *rq, void *context))
{
	(void)priority;
	queue->context = context;
	queue->fn = fn;
}

void xrp_queue_destroy(struct xrp_request_queue *queue)
{
	(void)queue;
}

void xrp_queue_push(struct xrp_request_queue *queue,
		    struct xrp_queue_item *rq)
{
	queue->fn(rq, queue->context);
}

struct xrp_event *xrp_event_create(void)
{
	struct xrp_event *event = alloc_refcounted(sizeof(*event));

	if (!event)
		return NULL;
	event->status = XRP_STATUS_PENDING;
	return event;
}

void xrp_wait(struct xrp_event *event, enum xrp_status *status)
{
	if (event->status == XRP_STATUS_PENDING)
		set_status(status, XRP_STATUS_FAILURE);
	else
		set_status(status, XRP_STATUS_SUCCESS);
}

size_t xrp_wait_any(struct xrp_event **event, size_t n_events,
		    enum xrp_status *status)
{
	if (n_events && event[0]->status != XRP_STATUS_PENDING)
		set_status(status, XRP_STATUS_SUCCESS);
	else
		set_status(status, XRP_STATUS_FAILURE);
	return 0;
}

void xrp_impl_broadcast_event(struct xrp_event *event, enum xrp_status status)
{
	event->status = status;
}

void xrp_impl_release_event(struct xrp_event *event)
{
	(void)event;
}
