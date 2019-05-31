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

#ifndef _XRP_SYNC_QUEUE_IMPL_H
#define _XRP_SYNC_QUEUE_IMPL_H

#include "xrp_thread_impl.h"

struct xrp_queue_item {
};

struct xrp_request_queue {
	void *context;
	void (*fn)(struct xrp_queue_item *rq, void *context);
};

struct xrp_event_impl {
	xrp_cond cond;
};

void xrp_queue_init(struct xrp_request_queue *queue, int priority,
		    void *context,
		    void (*fn)(struct xrp_queue_item *rq, void *context));
void xrp_queue_destroy(struct xrp_request_queue *queue);
void xrp_queue_push(struct xrp_request_queue *queue,
		    struct xrp_queue_item *rq);

struct xrp_event *xrp_event_create(void);
void xrp_impl_broadcast_event(struct xrp_event *event, enum xrp_status status);
void xrp_impl_release_event(struct xrp_event *event);

#endif
