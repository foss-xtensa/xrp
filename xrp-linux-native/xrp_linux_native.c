#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef uint32_t __u32;
typedef uint64_t __u64;

#include "xrp_api.h"
#include "xrp_kernel_defs.h"

struct xrp_refcounted {
	unsigned long count;
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
	unsigned long map_count;
	enum xrp_access_flags map_flags;
};

struct xrp_buffer_group_record {
	struct xrp_buffer *buffer;
	enum xrp_access_flags access_flags;
};

struct xrp_buffer_group {
	struct xrp_refcounted ref;
	size_t n_buffers;
	size_t capacity;
	struct xrp_buffer_group_record *buffer;
};

struct xrp_queue {
	struct xrp_refcounted ref;
	struct xrp_device *device;
};

struct xrp_event {
	struct xrp_refcounted ref;
	struct xrp_device *device;
	unsigned long cookie;
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
		++ref->count;
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
		buf->ptr = (void *)ioctl_alloc.addr;
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
				.addr = (__u64)buffer->ptr,
			};
			int ret = ioctl(buffer->device->fd,
					XRP_IOCTL_FREE, &ioctl_alloc);

			if (ret < 0) {
				set_status(status, XRP_STATUS_FAILURE);
				return;
			}
			xrp_release_device(buffer->device, &s);
		} else {
			free(buffer->ptr);
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
		release_refcounted(buffer);
		set_status(status, XRP_STATUS_SUCCESS);
	} else {
		set_status(status, XRP_STATUS_FAILURE);
	}
}


/* Buffer group API. */

struct xrp_buffer_group *xrp_create_buffer_group(enum xrp_status *status)
{
	struct xrp_buffer_group *group = alloc_refcounted(sizeof(*group));

	if (group)
		set_status(status, XRP_STATUS_SUCCESS);
	else
		set_status(status, XRP_STATUS_FAILURE);

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

		for (i = 0; i < group->n_buffers; ++i)
			xrp_release_buffer(group->buffer[i].buffer, NULL);
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

	if (group->n_buffers == group->capacity) {
		struct xrp_buffer_group_record *r =
			realloc(group->buffer,
				sizeof(struct xrp_buffer_group_record) *
				((group->capacity + 2) * 2));

		if (r == NULL) {
			set_status(status, XRP_STATUS_FAILURE);
			return -1;
		}
		group->buffer = r;
		group->capacity = (group->capacity + 2) * 2;
	}

	xrp_retain_buffer(buffer, &s);
	if (s != XRP_STATUS_SUCCESS) {
		set_status(status, s);
		return -1;
	}
	group->buffer[group->n_buffers].buffer = buffer;
	group->buffer[group->n_buffers].access_flags = access_flags;
	return group->n_buffers++;
}

struct xrp_buffer *xrp_get_buffer_from_group(struct xrp_buffer_group *group,
					     size_t idx,
					     enum xrp_status *status)
{
	if (idx < group->n_buffers) {
		set_status(status, XRP_STATUS_SUCCESS);

		return group->buffer[idx].buffer;
	}
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}


/* Queue API. */

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

		xrp_release_device(queue->device, &s);
		if (s != XRP_STATUS_SUCCESS) {
			set_status(status, s);
			return;
		}
	}
	set_status(status, release_refcounted(queue));
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

		xrp_release_device(event->device, &s);
		if (s != XRP_STATUS_SUCCESS) {
			set_status(status, s);
			return;
		}
	}
	set_status(status, release_refcounted(event));
}


/* Communication API */

void xrp_run_command_sync(struct xrp_queue *queue,
			  const void *in_data, size_t in_data_size,
			  void *out_data, size_t out_data_size,
			  struct xrp_buffer_group *buffer_group,
			  enum xrp_status *status)
{
	xrp_enqueue_command(queue, in_data, in_data_size,
			    out_data, out_data_size,
			    buffer_group, NULL, status);
}

void xrp_enqueue_command(struct xrp_queue *queue,
			 const void *in_data, size_t in_data_size,
			 void *out_data, size_t out_data_size,
			 struct xrp_buffer_group *buffer_group,
			 struct xrp_event **evt,
			 enum xrp_status *status)
{
	struct xrp_event *event = NULL;
	size_t n_buffers = buffer_group ? buffer_group->n_buffers : 0;
	struct xrp_ioctl_buffer ioctl_buffer[n_buffers];/* TODO */
	struct xrp_ioctl_queue ioctl_queue = {
		.in_data_size = in_data_size,
		.out_data_size = out_data_size,
		.buffer_size = n_buffers *
			sizeof(struct xrp_ioctl_buffer),
		.in_data_addr = (__u64)in_data,
		.out_data_addr = (__u64)out_data,
		.buffer_addr = (__u64)ioctl_buffer,
	};
	int ret;
	size_t i;

	for (i = 0; i < n_buffers; ++i) {
		if (buffer_group->buffer[i].buffer->map_count > 0) {
			set_status(status, XRP_STATUS_FAILURE);
			return;

		}
		ioctl_buffer[i] = (struct xrp_ioctl_buffer){
			.flags = buffer_group->buffer[i].access_flags,
			.size = buffer_group->buffer[i].buffer->size,
			.addr = (__u64)buffer_group->buffer[i].buffer->ptr,
		};
	}

	if (evt) {
		enum xrp_status s;

		event = alloc_refcounted(sizeof(*event));
		if (!event) {
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		xrp_retain_device(queue->device, &s);
		if (s != XRP_STATUS_SUCCESS) {
			set_status(status, s);
			release_refcounted(event);
			return;
		}
		event->device = queue->device;
	}

	ret = ioctl(queue->device->fd,
		    XRP_IOCTL_QUEUE, &ioctl_queue);

	if (ret < 0) {
		if (event)
			xrp_release_event(event, NULL);
		set_status(status, XRP_STATUS_FAILURE);
		return;
	}
	if (evt) {
		event->cookie = ioctl_queue.flags;
		*evt = event;
	}
	set_status(status, XRP_STATUS_SUCCESS);
}

void xrp_wait(struct xrp_event *event, enum xrp_status *status)
{
	struct xrp_ioctl_wait ioctl_wait = {
		.cookie = event->cookie,
	};
	int ret = ioctl(event->device->fd,
			XRP_IOCTL_WAIT, &ioctl_wait);

	if (ret < 0) {
		set_status(status, XRP_STATUS_FAILURE);
		return;
	}
	set_status(status, XRP_STATUS_SUCCESS);
}
