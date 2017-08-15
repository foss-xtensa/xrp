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

#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef uint32_t __u32;
typedef uint64_t __u64;

#include "xrp_api.h"
#include "xrp_kernel_defs.h"

#if defined(__STDC_NO_ATOMICS__)
#warning The compiler does not support atomics, reference counting may not be thread safe
#define _Atomic
#endif

struct xrp_refcounted {
	_Atomic unsigned long count;
};

struct xrp_device {
	struct xrp_refcounted ref;
	int fd;
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
};

struct xrp_buffer_group_record {
	struct xrp_buffer *buffer;
	enum xrp_access_flags access_flags;
};

struct xrp_buffer_group {
	struct xrp_refcounted ref;
	pthread_mutex_t mutex;
	size_t n_buffers;
	size_t capacity;
	struct xrp_buffer_group_record *buffer;
};

struct xrp_request {
	struct xrp_request *next;

	void *in_data;
	void *out_data;
	size_t in_data_size;
	size_t out_data_size;
	struct xrp_buffer_group *buffer_group;
	struct xrp_event *event;
};

struct xrp_queue {
	struct xrp_refcounted ref;
	struct xrp_device *device;

	pthread_t thread;
	pthread_mutex_t request_queue_mutex;
	pthread_cond_t request_queue_cond;
	struct {
		struct xrp_request *head;
		struct xrp_request *tail;
	} request_queue;
};

struct xrp_event {
	struct xrp_refcounted ref;
	struct xrp_queue *queue;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	_Atomic enum xrp_status status;
};

/* Helpers */

static inline void set_status(enum xrp_status *status, enum xrp_status v)
{
	if (status)
		*status = v;
}

static void *alloc_refcounted(size_t sz)
{
	void *buf = calloc(1, sz);
	struct xrp_refcounted *ref = buf;

	if (ref)
		ref->count = 1;

	return buf;
}

static enum xrp_status retain_refcounted(void *buf)
{
	struct xrp_refcounted *ref = buf;

	if (ref) {
		(void)++ref->count;
		return XRP_STATUS_SUCCESS;
	}
	return XRP_STATUS_FAILURE;
}

static enum xrp_status release_refcounted(void *buf)
{
	struct xrp_refcounted *ref = buf;

	if (ref) {
		if (--ref->count == 0)
			free(buf);
		return XRP_STATUS_SUCCESS;
	}
	return XRP_STATUS_FAILURE;
}

static inline int last_refcount(const void *buf)
{
	const struct xrp_refcounted *ref = buf;

	return ref->count == 1;
}


/* Device API. */

struct xrp_device *xrp_open_device(int idx, enum xrp_status *status)
{
	struct xrp_device *device;
	char name[sizeof("/dev/xvp") + sizeof(int) * 4];
	int fd;

	sprintf(name, "/dev/xvp%u", idx);
	fd = open(name, O_RDWR);
	if (fd == -1) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}
	device = alloc_refcounted(sizeof(*device));
	if (!device) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}
	device->fd = fd;
	set_status(status, XRP_STATUS_SUCCESS);
	return device;
}

void xrp_retain_device(struct xrp_device *device, enum xrp_status *status)
{
	set_status(status, retain_refcounted(device));
}

void xrp_release_device(struct xrp_device *device, enum xrp_status *status)
{
	if (last_refcount(device)) {
		if (close(device->fd) == -1) {
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
	}
	set_status(status, release_refcounted(device));
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
		struct xrp_ioctl_alloc ioctl_alloc = {
			.size = size,
		};
		int ret;
		enum xrp_status s;

		xrp_retain_device(device, &s);
		if (s != XRP_STATUS_SUCCESS) {
			release_refcounted(buf);
			set_status(status, s);
			return NULL;
		}
		buf->device = device;
		ret = ioctl(buf->device->fd, XRP_IOCTL_ALLOC, &ioctl_alloc);
		if (ret < 0) {
			xrp_release_device(buf->device, NULL);
			release_refcounted(buf);
			set_status(status, XRP_STATUS_FAILURE);
			return NULL;
		}
		buf->type = XRP_BUFFER_TYPE_DEVICE;
		buf->ptr = (void *)(uintptr_t)ioctl_alloc.addr;
		buf->size = size;
	} else {
		buf->type = XRP_BUFFER_TYPE_HOST;
		buf->ptr = host_ptr;
		buf->size = size;
	}
	return buf;
}

void xrp_retain_buffer(struct xrp_buffer *buffer, enum xrp_status *status)
{
	set_status(status, retain_refcounted(buffer));
}

void xrp_release_buffer(struct xrp_buffer *buffer, enum xrp_status *status)
{
	if (last_refcount(buffer)) {
		if (buffer->type == XRP_BUFFER_TYPE_DEVICE) {
			enum xrp_status s;
			struct xrp_ioctl_alloc ioctl_alloc = {
				.addr = (uintptr_t)buffer->ptr,
			};
			int ret = ioctl(buffer->device->fd,
					XRP_IOCTL_FREE, &ioctl_alloc);

			if (ret < 0) {
				set_status(status, XRP_STATUS_FAILURE);
				return;
			}
			xrp_release_device(buffer->device, &s);
		}
	}
	set_status(status, release_refcounted(buffer));
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
		return buffer->ptr + offset;
	}
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}

void xrp_unmap_buffer(struct xrp_buffer *buffer, void *p,
		      enum xrp_status *status)
{
	if (p >= buffer->ptr && (size_t)(p - buffer->ptr) <= buffer->size) {
		(void)--buffer->map_count;
		xrp_release_buffer(buffer, status);
	} else {
		set_status(status, XRP_STATUS_FAILURE);
	}
}


/* Buffer group API. */

struct xrp_buffer_group *xrp_create_buffer_group(enum xrp_status *status)
{
	struct xrp_buffer_group *group = alloc_refcounted(sizeof(*group));

	if (group) {
		pthread_mutex_init(&group->mutex, NULL);
		set_status(status, XRP_STATUS_SUCCESS);
	} else {
		set_status(status, XRP_STATUS_FAILURE);
	}

	return group;
}

void xrp_retain_buffer_group(struct xrp_buffer_group *group,
			     enum xrp_status *status)
{
	set_status(status, retain_refcounted(group));
}

void xrp_release_buffer_group(struct xrp_buffer_group *group,
			      enum xrp_status *status)
{
	if (last_refcount(group)) {
		size_t i;

		pthread_mutex_lock(&group->mutex);
		for (i = 0; i < group->n_buffers; ++i)
			xrp_release_buffer(group->buffer[i].buffer, NULL);
		pthread_mutex_unlock(&group->mutex);
		pthread_mutex_destroy(&group->mutex);
		free(group->buffer);
	}
	set_status(status, release_refcounted(group));
}

size_t xrp_add_buffer_to_group(struct xrp_buffer_group *group,
			       struct xrp_buffer *buffer,
			       enum xrp_access_flags access_flags,
			       enum xrp_status *status)
{
	enum xrp_status s;
	size_t n_buffers;

	pthread_mutex_lock(&group->mutex);
	if (group->n_buffers == group->capacity) {
		struct xrp_buffer_group_record *r =
			realloc(group->buffer,
				sizeof(struct xrp_buffer_group_record) *
				((group->capacity + 2) * 2));

		if (r == NULL) {
			pthread_mutex_unlock(&group->mutex);
			set_status(status, XRP_STATUS_FAILURE);
			return -1;
		}
		group->buffer = r;
		group->capacity = (group->capacity + 2) * 2;
	}

	xrp_retain_buffer(buffer, &s);
	if (s != XRP_STATUS_SUCCESS) {
		pthread_mutex_unlock(&group->mutex);
		set_status(status, s);
		return -1;
	}
	group->buffer[group->n_buffers].buffer = buffer;
	group->buffer[group->n_buffers].access_flags = access_flags;
	n_buffers = group->n_buffers++;
	pthread_mutex_unlock(&group->mutex);
	return n_buffers;
}

struct xrp_buffer *xrp_get_buffer_from_group(struct xrp_buffer_group *group,
					     size_t idx,
					     enum xrp_status *status)
{
	struct xrp_buffer *buffer = NULL;

	pthread_mutex_lock(&group->mutex);
	if (idx < group->n_buffers) {
		buffer = group->buffer[idx].buffer;
		xrp_retain_buffer(buffer, status);
	} else {
		set_status(status, XRP_STATUS_FAILURE);
	}
	pthread_mutex_unlock(&group->mutex);
	return buffer;
}


/* Queue API. */

static void xrp_queue_process(struct xrp_queue *queue);

static void *xrp_queue_thread(void *p)
{
	struct xrp_queue *queue = p;

	for (;;)
		xrp_queue_process(queue);

	return NULL;
}

struct xrp_queue *xrp_create_queue(struct xrp_device *device,
				   enum xrp_status *status)
{
	struct xrp_queue *queue;
	enum xrp_status s;

	if (!device) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	queue = alloc_refcounted(sizeof(*queue));

	if (!queue) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	xrp_retain_device(device, &s);
	if (s != XRP_STATUS_SUCCESS) {
		set_status(status, s);
		release_refcounted(queue);
		return NULL;
	}
	queue->device = device;

	pthread_mutex_init(&queue->request_queue_mutex, NULL);
	pthread_cond_init(&queue->request_queue_cond, NULL);
	pthread_create(&queue->thread, NULL, xrp_queue_thread, queue);

	return queue;
}

void xrp_retain_queue(struct xrp_queue *queue, enum xrp_status *status)
{
	set_status(status, retain_refcounted(queue));
}

void xrp_release_queue(struct xrp_queue *queue, enum xrp_status *status)
{
	if (last_refcount(queue)) {
		enum xrp_status s;

		pthread_cancel(queue->thread);
		pthread_join(queue->thread, NULL);
		pthread_mutex_lock(&queue->request_queue_mutex);
		if (queue->request_queue.head != NULL)
			printf("%s: releasing non-empty queue\n", __func__);
		pthread_mutex_unlock(&queue->request_queue_mutex);
		pthread_mutex_destroy(&queue->request_queue_mutex);
		pthread_cond_destroy(&queue->request_queue_cond);
		xrp_release_device(queue->device, &s);
		if (s != XRP_STATUS_SUCCESS) {
			set_status(status, s);
			return;
		}
	}
	set_status(status, release_refcounted(queue));
}

static void xrp_enqueue_request(struct xrp_queue *queue,
				struct xrp_request *rq)
{
	pthread_mutex_lock(&queue->request_queue_mutex);
	rq->next = NULL;
	if (queue->request_queue.tail) {
		queue->request_queue.tail->next = rq;
	} else {
		queue->request_queue.head = rq;
		pthread_cond_broadcast(&queue->request_queue_cond);
	}
	queue->request_queue.tail = rq;
	pthread_mutex_unlock(&queue->request_queue_mutex);
}

static struct xrp_request *_xrp_dequeue_request(struct xrp_queue *queue)
{
	struct xrp_request *rq = queue->request_queue.head;

	if (!rq)
		return NULL;

	if (rq == queue->request_queue.tail)
		queue->request_queue.tail = NULL;
	queue->request_queue.head = rq->next;
	return rq;
}

static void _xrp_run_command(struct xrp_queue *queue,
			     const void *in_data, size_t in_data_size,
			     void *out_data, size_t out_data_size,
			     struct xrp_buffer_group *buffer_group,
			     enum xrp_status *status)
{
	int ret;

	if (buffer_group)
		pthread_mutex_lock(&buffer_group->mutex);
	{
		size_t n_buffers = buffer_group ? buffer_group->n_buffers : 0;
		struct xrp_ioctl_buffer ioctl_buffer[n_buffers];/* TODO */
		struct xrp_ioctl_queue ioctl_queue = {
			.in_data_size = in_data_size,
			.out_data_size = out_data_size,
			.buffer_size = n_buffers *
				sizeof(struct xrp_ioctl_buffer),
			.in_data_addr = (uintptr_t)in_data,
			.out_data_addr = (uintptr_t)out_data,
			.buffer_addr = (uintptr_t)ioctl_buffer,
		};
		size_t i;

		for (i = 0; i < n_buffers; ++i) {
			if (buffer_group->buffer[i].buffer->map_count > 0) {
				pthread_mutex_unlock(&buffer_group->mutex);
				set_status(status, XRP_STATUS_FAILURE);
				return;

			}
			ioctl_buffer[i] = (struct xrp_ioctl_buffer){
				.flags = buffer_group->buffer[i].access_flags,
				.size = buffer_group->buffer[i].buffer->size,
				.addr = (uintptr_t)buffer_group->buffer[i].buffer->ptr,
			};
		}
		if (buffer_group)
			pthread_mutex_unlock(&buffer_group->mutex);

		ret = ioctl(queue->device->fd,
			    XRP_IOCTL_QUEUE, &ioctl_queue);
	}

	if (ret < 0)
		set_status(status, XRP_STATUS_FAILURE);
	else
		set_status(status, XRP_STATUS_SUCCESS);
}

static void xrp_queue_cleanup(void *p)
{
	struct xrp_queue *queue = p;
	pthread_mutex_unlock(&queue->request_queue_mutex);
}

static void xrp_queue_process(struct xrp_queue *queue)
{
	struct xrp_request *rq;
	enum xrp_status status;
	int old_state;

	pthread_mutex_lock(&queue->request_queue_mutex);
	pthread_cleanup_push(xrp_queue_cleanup, queue);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old_state);
	for (;;) {
		rq = _xrp_dequeue_request(queue);
		if (rq)
			break;
		pthread_cond_wait(&queue->request_queue_cond,
				  &queue->request_queue_mutex);
	}
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	pthread_cleanup_pop(1);

	_xrp_run_command(queue,
			 rq->in_data, rq->in_data_size,
			 rq->out_data, rq->out_data_size,
			 rq->buffer_group,
			 &status);

	if (rq->buffer_group)
		xrp_release_buffer_group(rq->buffer_group, NULL);

	if (rq->event) {
		struct xrp_event *event = rq->event;
		pthread_mutex_lock(&event->mutex);
		event->status = status;
		pthread_cond_broadcast(&event->cond);
		pthread_mutex_unlock(&event->mutex);
		xrp_release_event(event, NULL);
	}
	free(rq->in_data);
	free(rq);
	pthread_setcancelstate(old_state, NULL);
}


/* Event API. */

void xrp_retain_event(struct xrp_event *event, enum xrp_status *status)
{
	set_status(status, retain_refcounted(event));
}

void xrp_release_event(struct xrp_event *event, enum xrp_status *status)
{
	if (last_refcount(event)) {
		enum xrp_status s;

		xrp_release_queue(event->queue, &s);
		if (s != XRP_STATUS_SUCCESS) {
			set_status(status, s);
			return;
		}
		pthread_mutex_destroy(&event->mutex);
		pthread_cond_destroy(&event->cond);
	}
	set_status(status, release_refcounted(event));
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
	xrp_release_event(evt, NULL);
}

void xrp_enqueue_command(struct xrp_queue *queue,
			 const void *in_data, size_t in_data_size,
			 void *out_data, size_t out_data_size,
			 struct xrp_buffer_group *buffer_group,
			 struct xrp_event **evt,
			 enum xrp_status *status)
{
	struct xrp_request *rq;
	void *in_data_copy;
	struct xrp_event *event = NULL;

	rq = malloc(sizeof(*rq));
	in_data_copy = malloc(in_data_size);

	if (!rq || (in_data_size && !in_data_copy)) {
		free(in_data_copy);
		free(rq);
		set_status(status, XRP_STATUS_FAILURE);
		return;
	}

	memcpy(in_data_copy, in_data, in_data_size);
	rq->in_data = in_data_copy;
	rq->in_data_size = in_data_size;
	rq->out_data = out_data;
	rq->out_data_size = out_data_size;

	if (evt) {
		enum xrp_status s;

		event = alloc_refcounted(sizeof(*event));
		if (!event) {
			free(rq->in_data);
			free(rq);
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		xrp_retain_queue(queue, &s);
		if (s != XRP_STATUS_SUCCESS) {
			free(rq->in_data);
			free(rq);
			set_status(status, s);
			release_refcounted(event);
			return;
		}
		event->queue = queue;
		pthread_mutex_init(&event->mutex, NULL);
		pthread_cond_init(&event->cond, NULL);
		event->status = XRP_STATUS_PENDING;
		*evt = event;
		xrp_retain_event(event, NULL);
		rq->event = event;
	} else {
		rq->event = NULL;
	}

	if (buffer_group)
		xrp_retain_buffer_group(buffer_group, NULL);
	rq->buffer_group = buffer_group;

	xrp_enqueue_request(queue, rq);

	set_status(status, XRP_STATUS_SUCCESS);
}

void xrp_wait(struct xrp_event *event, enum xrp_status *status)
{
	pthread_mutex_lock(&event->mutex);
	while (event->status == XRP_STATUS_PENDING)
		pthread_cond_wait(&event->cond, &event->mutex);
	pthread_mutex_unlock(&event->mutex);
	set_status(status, XRP_STATUS_SUCCESS);
}
