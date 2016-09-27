#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "xrp_api.h"

struct xrp_refcounted {
	unsigned long count;
};

struct xrp_device {
	struct xrp_refcounted ref;
	int fd;
};

struct xrp_buffer {
	struct xrp_refcounted ref;
	enum {
		XRP_BUFFER_TYPE_HOST,
		XRP_BUFFER_TYPE_DEVICE,
	} type;
	void *ptr;
	size_t size;
	unsigned long map_count;
};

struct xrp_buffer_group_record {
	struct xrp_buffer *buffer;
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
		buf->type = XRP_BUFFER_TYPE_DEVICE;
		/* TODO implement device-specific allocation */
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
			/* TODO implement device-specific freeing */
		} else {
			free(buffer->ptr);
		}
	}
	set_status(status, release_refcounted(buffer));
}

void *xrp_map_buffer(struct xrp_buffer *buffer, size_t offset, size_t size,
		     enum xrp_map_flags map_flags, enum xrp_status *status)
{
	if (offset <= buffer->size &&
	    size <= buffer->size - offset) {
		retain_refcounted(buffer);
		++buffer->map_count;
		set_status(status, XRP_STATUS_SUCCESS);
		return buffer->ptr + offset;
	}
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}

void xrp_unmap_buffer(struct xrp_buffer *buffer, void *p,
		      enum xrp_status *status)
{
	if (p >= buffer->ptr && p - buffer->ptr <= buffer->size) {
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

int xrp_add_buffer_to_group(struct xrp_buffer_group *group,
			    struct xrp_buffer *buffer,
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
	return group->n_buffers++;
}

struct xrp_buffer *xrp_get_buffer_from_group(struct xrp_buffer_group *group,
					     int idx,
					     enum xrp_status *status)
{
	if (idx >= 0 && idx < group->n_buffers) {
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


/* Communication API */

void xrp_queue_command(struct xrp_queue *queue,
		       void *data, size_t data_sz,
		       struct xrp_buffer_group *buffer_group,
		       struct xrp_event **evt,
		       enum xrp_status *status)
{
}

void xrp_wait(struct xrp_event *event, enum xrp_status *status)
{
}
