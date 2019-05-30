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
#include "xrp_debug.h"
#include "xrp_host_common.h"
#include "xrp_threaded_queue.h"

static struct xrp_queue_item *_xrp_dequeue_request(struct xrp_request_queue *queue)
{
	struct xrp_queue_item *rq = queue->request_queue.head;

	if (!rq)
		return NULL;

	if (rq == queue->request_queue.tail)
		queue->request_queue.tail = NULL;
	queue->request_queue.head = rq->next;
	return rq;
}

static int xrp_queue_process(struct xrp_request_queue *queue)
{
	struct xrp_queue_item *rq;
	int exit = 0;

	queue->sync_exit = &exit;
	xrp_cond_lock(&queue->request_queue_cond);
	for (;;) {
		rq = _xrp_dequeue_request(queue);
		if (rq || queue->exit)
			break;
		xrp_cond_wait(&queue->request_queue_cond);
	}
	xrp_cond_unlock(&queue->request_queue_cond);

	if (!rq)
		return 0;

	queue->fn(rq, queue->context);

	return !exit;
}

static void *xrp_queue_thread(void *p)
{
	struct xrp_request_queue *queue = p;

	while (xrp_queue_process(queue)) {
	}

	return NULL;
}

void xrp_queue_init(struct xrp_request_queue *queue, int priority,
		    void *context,
		    void (*fn)(struct xrp_queue_item *rq, void *context))
{
	xrp_cond_init(&queue->request_queue_cond);
	queue->context = context;
	queue->fn = fn;
	xrp_thread_create(&queue->thread, priority, xrp_queue_thread, queue);
}

void xrp_queue_destroy(struct xrp_request_queue *queue)
{
	xrp_cond_lock(&queue->request_queue_cond);
	queue->exit = 1;
	xrp_cond_broadcast(&queue->request_queue_cond);
	xrp_cond_unlock(&queue->request_queue_cond);
	if (!xrp_thread_join(&queue->thread)) {
		*queue->sync_exit = 1;
		xrp_thread_detach(&queue->thread);
	}
	xrp_cond_lock(&queue->request_queue_cond);
	if (queue->request_queue.head != NULL)
		printf("%s: releasing non-empty queue\n", __func__);
	xrp_cond_unlock(&queue->request_queue_cond);
	xrp_cond_destroy(&queue->request_queue_cond);
}

void xrp_queue_push(struct xrp_request_queue *queue,
		    struct xrp_queue_item *rq)
{
	xrp_cond_lock(&queue->request_queue_cond);
	rq->next = NULL;
	if (queue->request_queue.tail) {
		queue->request_queue.tail->next = rq;
	} else {
		queue->request_queue.head = rq;
		xrp_cond_broadcast(&queue->request_queue_cond);
	}
	queue->request_queue.tail = rq;
	xrp_cond_unlock(&queue->request_queue_cond);
}

static void xrp_impl_event_init(struct xrp_event *event)
{
	xrp_cond_init(&event->impl.cond);
	event->status = XRP_STATUS_PENDING;
}

struct xrp_event *xrp_event_create(void)
{
	struct xrp_event *event = alloc_refcounted(sizeof(*event));

	if (!event)
		return NULL;
	xrp_impl_event_init(event);
	return event;
}

void xrp_wait(struct xrp_event *event, enum xrp_status *status)
{
	xrp_cond_lock(&event->impl.cond);
	while (event->status == XRP_STATUS_PENDING)
		xrp_cond_wait(&event->impl.cond);
	xrp_cond_unlock(&event->impl.cond);
	set_status(status, XRP_STATUS_SUCCESS);
}

size_t xrp_wait_any(struct xrp_event **event, size_t n_events,
		    enum xrp_status *status)
{
	size_t i, rv;
	struct xrp_event group;
	struct xrp_event_link *link;

	if (!n_events) {
		set_status(status, XRP_STATUS_FAILURE);
		return 0;
	}

	link = calloc(n_events, sizeof(struct xrp_event_link));

	xrp_impl_event_init(&group);

	for (i = 0; i < n_events; ++i) {
		xrp_cond_lock(&event[i]->impl.cond);
		if (event[i]->status == XRP_STATUS_PENDING) {
			link[i].group = event[i]->group;
			link[i].next = event[i]->link;

			if (event[i]->link)
				event[i]->link->prev = link + i;

			event[i]->group = &group;
			event[i]->link = link + i;
		} else {
			xrp_cond_unlock(&event[i]->impl.cond);
			break;
		}
		xrp_cond_unlock(&event[i]->impl.cond);
	}

	rv = i;

	if (i == n_events)
		xrp_wait(&group, NULL);
	else
		n_events = i;

	for (i = 0; i < n_events; ++i) {
		xrp_cond_lock(&event[i]->impl.cond);
		if (event[i]->group == &group) {
			event[i]->group = link[i].group;
			event[i]->link = link[i].next;
		}
		if (link[i].next) {
			link[i].next->prev = link[i].prev;
		}
		if (link[i].prev) {
			if (link[i].prev->group == &group) {
				link[i].prev->group = link[i].group;
				link[i].prev->next = link[i].next;
			} else {
				pr_debug("%s: inconsistent link state\n");
			}
		}
		if (event[i]->status != XRP_STATUS_PENDING)
			rv = i;
		xrp_cond_unlock(&event[i]->impl.cond);
	}
	xrp_impl_release_event(&group);
	free(link);
	set_status(status, XRP_STATUS_SUCCESS);
	return rv;
}

void xrp_impl_broadcast_event(struct xrp_event *event, enum xrp_status status)
{
	struct xrp_event *group;
	struct xrp_event_link *link;

	xrp_cond_lock(&event->impl.cond);
	event->status = status;
	xrp_cond_broadcast(&event->impl.cond);

	group = event->group;
	link = event->link;
	while (link) {
		xrp_cond_lock(&group->impl.cond);
		group->status = status;
		xrp_cond_broadcast(&group->impl.cond);
		xrp_cond_unlock(&group->impl.cond);
		group = link->group;
		link = link->next;
	}
	xrp_cond_unlock(&event->impl.cond);
}

void xrp_impl_release_event(struct xrp_event *event)
{
	xrp_cond_destroy(&event->impl.cond);
}
