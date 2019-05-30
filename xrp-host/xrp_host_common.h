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

#ifndef _XRP_HOST_COMMON_H
#define _XRP_HOST_COMMON_H

#include <stdlib.h>
#include "xrp_atomic.h"
#include "xrp_thread_impl.h"
#include "xrp_host_impl.h"

struct xrp_refcounted {
	_Atomic unsigned long count;
};

struct xrp_device {
	struct xrp_refcounted ref;
	struct xrp_device_impl impl;
};

struct xrp_buffer {
	struct xrp_refcounted ref;
	struct xrp_device *device;
	enum {
		XRP_BUFFER_TYPE_HOST,
		XRP_BUFFER_TYPE_DEVICE,
	} type;
	void *ptr;
	size_t size;
	_Atomic unsigned long map_count;
	enum xrp_access_flags map_flags;
	struct xrp_buffer_impl impl;
};

struct xrp_buffer_group_record {
	struct xrp_buffer *buffer;
	enum xrp_access_flags access_flags;
};

struct xrp_buffer_group {
	struct xrp_refcounted ref;
	xrp_mutex mutex;
	size_t n_buffers;
	size_t capacity;
	struct xrp_buffer_group_record *buffer;
};

struct xrp_queue {
	struct xrp_refcounted ref;
	struct xrp_device *device;
	int use_nsid;
	int priority;
	char nsid[XRP_NAMESPACE_ID_SIZE];
	struct xrp_queue_impl impl;
};

struct xrp_event_link {
	struct xrp_event *group;
	struct xrp_event_link *next, *prev;
};

struct xrp_event {
	struct xrp_refcounted ref;
	struct xrp_queue *queue;
	_Atomic enum xrp_status status;
	struct xrp_event_impl impl;
	struct xrp_event *group;
	struct xrp_event_link *link;
};

/* Helpers */

static inline void set_status(enum xrp_status *status, enum xrp_status v)
{
	if (status)
		*status = v;
}

static inline void *alloc_refcounted(size_t sz)
{
	void *buf = calloc(1, sz);
	struct xrp_refcounted *ref = buf;

	if (ref)
		ref->count = 1;

	return buf;
}

static inline void retain_refcounted(void *buf)
{
	struct xrp_refcounted *ref = buf;
	(void)++ref->count;
}

static inline int last_release_refcounted(void *buf)
{
	struct xrp_refcounted *ref = buf;
	return --ref->count == 0;
}

#endif
