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
#include <libfdt.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_DEFINED(a, b) ((void)(a),(void)(b))
#endif

#define barrier() asm volatile ("" ::: "memory")
#define mb() barrier()
#define schedule() barrier()

typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;

#include "xrp_api.h"
#include "../xrp-kernel/xrp_kernel_dsp_interface.h"
#include "xrp_alloc.h"

#if defined(__STDC_NO_ATOMICS__)
#warning The compiler does not support atomics, reference counting may not be thread safe
#define _Atomic
#endif

enum {
	XRP_IRQ_NONE,
	XRP_IRQ_LEVEL,
	XRP_IRQ_EDGE,
	XRP_IRQ_MAX,
};

extern char dt_blob_start[];

struct xrp_shmem {
	phys_addr_t start;
	phys_addr_t size;
	const char *name;
	int fd;
	void *ptr;
};

static struct xrp_shmem *xrp_shmem;
static int xrp_shmem_count;

struct xrp_device_description {
	phys_addr_t io_base;
	phys_addr_t comm_base;
	phys_addr_t shared_base;
	phys_addr_t shared_size;
	void *comm_ptr;
	void *shared_ptr;

	uint32_t device_irq_mode;
	uint32_t device_irq[3];
	pthread_mutex_t hw_mutex;
};

static struct xrp_device_description xrp_device_description[4];
static int xrp_device_count;
static phys_addr_t xrp_exit_loc;

struct xrp_refcounted {
	_Atomic unsigned long count;
};

struct xrp_request {
	struct xrp_request *next;
	struct xrp_dsp_cmd dsp_cmd;

	size_t in_data_size;
	void *out_data;
	void *out_data_ptr;
	size_t out_data_size;
	struct xrp_buffer_group *buffer_group;
	struct xrp_event *event;

	struct xrp_allocation *in_data_allocation;
	struct xrp_allocation *out_data_allocation;
	struct xrp_allocation *buffer_allocation;
	struct xrp_allocation **user_buffer_allocation;
	struct xrp_dsp_buffer *buffer_ptr;
};

struct xrp_device {
	struct xrp_refcounted ref;
	struct xrp_device_description *description;
	struct xrp_allocation_pool shared_pool;

	pthread_t thread;
	pthread_mutex_t request_queue_mutex;
	pthread_cond_t request_queue_cond;
	struct {
		struct xrp_request *head;
		struct xrp_request *tail;
	} request_queue;
};

struct xrp_buffer {
	struct xrp_refcounted ref;
	struct xrp_device *device;
	enum {
		XRP_BUFFER_TYPE_HOST,
		XRP_BUFFER_TYPE_DEVICE,
	} type;
	struct xrp_allocation *xrp_allocation;
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
	pthread_mutex_t mutex;
	pthread_cond_t cond;
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

static inline void xrp_comm_write32(volatile void *addr, __u32 v)
{
	*(volatile __u32 *)addr = v;
}

static inline __u32 xrp_comm_read32(volatile void *addr)
{
	return *(volatile __u32 *)addr;
}

static uint32_t getprop_u32(const void *value, int offset)
{
	fdt32_t v;

	memcpy(&v, value + offset, sizeof(v));
	return fdt32_to_cpu(v);
}

static struct xrp_shmem *find_shmem(phys_addr_t addr)
{
	int i;

	for (i = 0; i < xrp_shmem_count; ++i) {
		if (addr >= xrp_shmem[i].start &&
		    addr - xrp_shmem[i].start < xrp_shmem[i].size)
			return xrp_shmem + i;
	}
	return NULL;
}

static void *p2v(phys_addr_t addr)
{
	struct xrp_shmem *shmem = find_shmem(addr);

	if (shmem) {
		return shmem->ptr + addr - shmem->start;
	} else {
		return NULL;
	}
}

static void initialize_shmem(void)
{
	void *fdt = &dt_blob_start;
	const void *reg;
	const void *names;
	int reg_len, names_len;
	int offset, reg_offset = 0, name_offset = 0;
	int i;

	offset = fdt_node_offset_by_compatible(fdt,
					       -1, "cdns,sim-shmem");
	if (offset < 0) {
		printf("%s: cdns,sim-shmem device not found\n", __func__);
		return;
	}
	reg = fdt_getprop(fdt, offset, "reg", &reg_len);
	if (!reg) {
		printf("%s: fdt_getprop \"reg\": %s\n",
		       __func__, fdt_strerror(reg_len));
		return;
	}
	names = fdt_getprop(fdt, offset, "reg-names", &names_len);
	if (!names) {
		printf("%s: fdt_getprop \"reg-names\": %s\n",
		       __func__, fdt_strerror(names_len));
		return;
	}
	xrp_shmem_count = reg_len / 8;
	xrp_shmem = malloc(xrp_shmem_count * sizeof(struct xrp_shmem));

	for (i = 0; i < xrp_shmem_count; ++i) {
		const char *name_fmt = names + name_offset;
		char *name = NULL;
		int sz = strlen(names + name_offset) + sizeof(int) * 3 + 1;
		int rc;

		for (;;) {
			name = realloc(name, sz);
			rc = snprintf(name, sz, name_fmt, (int)getpid());
			if (rc < sz)
				break;
			sz = rc + 1;
		}

		xrp_shmem[i] = (struct xrp_shmem){
			.start = getprop_u32(reg, reg_offset),
			.size = getprop_u32(reg, reg_offset + 4),
			.name = name,
		};
		reg_offset += 8;
		name_offset += strlen(names + name_offset) + 1;

		xrp_shmem[i].fd = shm_open(xrp_shmem[i].name,
					   O_RDWR | O_CREAT, 0666);
		if (xrp_shmem[i].fd < 0) {
			perror("shm_open");
			break;
		}
		rc = ftruncate(xrp_shmem[i].fd, xrp_shmem[i].size);
		if (rc < 0) {
			perror("ftruncate");
			break;
		}
		xrp_shmem[i].ptr = mmap(NULL, xrp_shmem[i].size,
					PROT_READ | PROT_WRITE,
					MAP_SHARED, xrp_shmem[i].fd, 0);
		if (xrp_shmem[i].ptr == MAP_FAILED) {
			perror("mmap");
			break;
		}
	}
	reg = fdt_getprop(fdt, offset, "exit-loc", &reg_len);
	if (!reg) {
		printf("%s: fdt_getprop \"exit-loc\": %s\n",
		       __func__, fdt_strerror(reg_len));
		return;
	}
	xrp_exit_loc = getprop_u32(reg, 0);
}

static inline void xrp_send_device_irq(struct xrp_device_description *desc)
{
	void *device_irq = p2v(desc->io_base + desc->device_irq[0]);

	switch (desc->device_irq_mode) {
	case XRP_IRQ_EDGE:
		xrp_comm_write32(device_irq, 0);
		/* fallthrough */
	case XRP_IRQ_LEVEL:
		mb();
		xrp_comm_write32(device_irq, 1 << desc->device_irq[1]);
		break;
	default:
		break;
	}
}


static void synchronize(struct xrp_device_description *desc)
{
	static const int irq_mode[] = {
		[XRP_IRQ_NONE] = XRP_DSP_SYNC_IRQ_MODE_NONE,
		[XRP_IRQ_LEVEL] = XRP_DSP_SYNC_IRQ_MODE_LEVEL,
		[XRP_IRQ_EDGE] = XRP_DSP_SYNC_IRQ_MODE_EDGE,
	};

	struct xrp_dsp_sync *shared_sync = desc->comm_ptr;

	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_START);
	mb();
	do {
		__u32 v = xrp_comm_read32(&shared_sync->sync);
		if (v == XRP_DSP_SYNC_DSP_READY)
			break;
		schedule();
	} while (1);

	xrp_comm_write32(&shared_sync->device_mmio_base,
			 desc->io_base);
	xrp_comm_write32(&shared_sync->host_irq_mode,
			 irq_mode[0]);
	xrp_comm_write32(&shared_sync->host_irq_offset,
			 0);
	xrp_comm_write32(&shared_sync->host_irq_bit,
			 0);
	xrp_comm_write32(&shared_sync->device_irq_mode,
			 irq_mode[desc->device_irq_mode]);
	xrp_comm_write32(&shared_sync->device_irq_offset,
			 desc->device_irq[0]);
	xrp_comm_write32(&shared_sync->device_irq_bit,
			 desc->device_irq[1]);
	xrp_comm_write32(&shared_sync->device_irq,
			 desc->device_irq[2]);
	mb();
	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_HOST_TO_DSP);
	mb();

	do {
		__u32 v = xrp_comm_read32(&shared_sync->sync);
		if (v == XRP_DSP_SYNC_DSP_TO_HOST)
			break;
		schedule();
	} while (1);

	xrp_send_device_irq(desc);

#if 0
	if (xvp->host_irq_mode != XRP_IRQ_NONE) {
		int res = wait_for_completion_timeout(&xvp->completion,
						      XVP_TIMEOUT_JIFFIES);
		if (res == 0) {
			dev_err(xvp->dev,
				"host IRQ mode is requested, but DSP couldn't deliver IRQ during synchronization\n");
			goto err;
		}
	}
#endif
	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_IDLE);

}

static void initialize(void)
{
	int i;
	int offset = -1;
	void *fdt = &dt_blob_start;

	initialize_shmem();

	for (i = 0; ; ++i) {
		const void *reg;
		const void *device_irq;
		const void *device_irq_mode;
		int len;

		offset = fdt_node_offset_by_compatible(fdt,
						       offset, "cdns,xrp");
		if (offset < 0)
			break;

		reg = fdt_getprop(fdt, offset, "reg", &len);
		if (!reg) {
			printf("%s: %s\n", __func__, fdt_strerror(len));
			break;
		}
		if (len < 24) {
			printf("%s: reg property size is too small (%d)\n",
			       __func__, len);
			break;
		}

		xrp_device_description[i] = (struct xrp_device_description){
			.io_base = getprop_u32(reg, 0),
			.comm_base = getprop_u32(reg, 8),
			.shared_base = getprop_u32(reg, 16),
			.shared_size = getprop_u32(reg, 20),
			.hw_mutex = PTHREAD_MUTEX_INITIALIZER,
		};

		device_irq_mode = fdt_getprop(fdt, offset, "device-irq-mode", &len);
		if (!device_irq_mode || len < 4) {
			printf("%s: valid device-irq-mode not found, not using\n",
			       __func__);
			device_irq_mode = NULL;
		}
		if (device_irq_mode && getprop_u32(device_irq_mode, 0)) {
			device_irq = fdt_getprop(fdt, offset, "device-irq", &len);
			if (!device_irq || len < 12) {
				printf("%s: valid device-irq not found, not using\n",
				       __func__);
				device_irq_mode = NULL;
				device_irq = NULL;
			} else {
				xrp_device_description[i].device_irq_mode =
					getprop_u32(device_irq_mode, 0);
				xrp_device_description[i].device_irq[0] =
					getprop_u32(device_irq, 0);
				xrp_device_description[i].device_irq[1] =
					getprop_u32(device_irq, 4);
				xrp_device_description[i].device_irq[2] =
					getprop_u32(device_irq, 8);
			}
		}
		xrp_device_description[i].comm_ptr =
			p2v(xrp_device_description[i].comm_base);
		if (!xrp_device_description[i].comm_ptr) {
			printf("%s: shmem not found for comm area @0x%08x\n",
			       __func__, xrp_device_description[i].comm_base);
			break;
		}

		xrp_device_description[i].shared_ptr =
			p2v(xrp_device_description[i].shared_base);
		if (!xrp_device_description[i].shared_ptr) {
			printf("%s: shmem not found for shared area @0x%08x\n",
			       __func__, xrp_device_description[i].shared_base);
			break;
		}

		synchronize(xrp_device_description + i);
		++xrp_device_count;
	}

}

/* Device API. */

static void xrp_queue_process(struct xrp_device *device);

static void *xrp_device_thread(void *p)
{
	struct xrp_device *device = p;

	for (;;)
		xrp_queue_process(device);

	return NULL;
}

struct xrp_device *xrp_open_device(int idx, enum xrp_status *status)
{
	struct xrp_device *device;

	if (!xrp_device_count) {
		initialize();
	}

	if (idx < 0 || idx > xrp_device_count) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	device = alloc_refcounted(sizeof(*device));
	if (!device) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}
	device->description = xrp_device_description + idx;
	xrp_init_pool(&device->shared_pool,
		      device->description->shared_base,
		      device->description->shared_size);

	pthread_mutex_init(&device->request_queue_mutex, NULL);
	pthread_cond_init(&device->request_queue_cond, NULL);
	pthread_create(&device->thread, NULL, xrp_device_thread, device);
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
		pthread_cancel(device->thread);
		pthread_join(device->thread, NULL);
		pthread_mutex_lock(&device->request_queue_mutex);
		if (device->request_queue.head != NULL)
			printf("%s: releasing a device with non-empty queue\n",
			       __func__);
		pthread_mutex_unlock(&device->request_queue_mutex);
		xrp_free_pool(&device->shared_pool);
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
		long rc = xrp_allocate(&device->shared_pool, size, 0x10,
				       &buf->xrp_allocation);
		if (rc < 0) {
			release_refcounted(buf);
			set_status(status, XRP_STATUS_FAILURE);
			return NULL;
		}
		buf->type = XRP_BUFFER_TYPE_DEVICE;
		buf->ptr = p2v(buf->xrp_allocation->start);
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
			xrp_free(buffer->xrp_allocation);
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
	struct xrp_event *evt;
	xrp_enqueue_command(queue, in_data, in_data_size,
			    out_data, out_data_size,
			    buffer_group, &evt, status);
	if (*status != XRP_STATUS_SUCCESS)
		return;
	xrp_wait(evt, NULL);
	xrp_release_event(evt, NULL);
}

static void xrp_enqueue_request(struct xrp_device *device,
				struct xrp_request *rq)
{
	pthread_mutex_lock(&device->request_queue_mutex);
	rq->next = NULL;
	if (device->request_queue.tail) {
		device->request_queue.tail->next = rq;
	} else {
		device->request_queue.head = rq;
		pthread_cond_broadcast(&device->request_queue_cond);
	}
	device->request_queue.tail = rq;
	pthread_mutex_unlock(&device->request_queue_mutex);
}

static struct xrp_request *_xrp_dequeue_request(struct xrp_device *device)
{
	struct xrp_request *rq = device->request_queue.head;

	if (!rq)
		return NULL;

	if (rq == device->request_queue.tail)
		device->request_queue.tail = NULL;
	device->request_queue.head = rq->next;
	return rq;
}

static void xrp_queue_cleanup(void *p)
{
	struct xrp_device *device = p;
	pthread_mutex_unlock(&device->request_queue_mutex);
}

static void xrp_queue_process(struct xrp_device *device)
{
	size_t n_buffers;
	struct xrp_dsp_cmd *dsp_cmd = device->description->comm_ptr;
	struct xrp_request *rq;
	size_t i;
	int old_state;

	pthread_mutex_lock(&device->request_queue_mutex);
	pthread_cleanup_push(xrp_queue_cleanup, device);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old_state);
	for (;;) {
		rq = _xrp_dequeue_request(device);
		if (rq)
			break;
		pthread_cond_wait(&device->request_queue_cond,
				  &device->request_queue_mutex);
	}
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	pthread_cleanup_pop(1);

	pthread_mutex_lock(&device->description->hw_mutex);
	memcpy(dsp_cmd, &rq->dsp_cmd, sizeof(rq->dsp_cmd));
	barrier();
	xrp_comm_write32(&dsp_cmd->flags, XRP_DSP_CMD_FLAG_REQUEST_VALID);
	barrier();
	xrp_send_device_irq(device->description);
	do {
		barrier();
	} while (xrp_comm_read32(&dsp_cmd->flags) !=
		 (XRP_DSP_CMD_FLAG_REQUEST_VALID |
		  XRP_DSP_CMD_FLAG_RESPONSE_VALID));

	memcpy(&rq->dsp_cmd, dsp_cmd, sizeof(rq->dsp_cmd));
	VALGRIND_MAKE_MEM_DEFINED(rq->out_data_ptr, rq->out_data_size);
	memcpy(rq->out_data, rq->out_data_ptr, rq->out_data_size);
	pthread_mutex_unlock(&device->description->hw_mutex);

	if (rq->in_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		xrp_free(rq->in_data_allocation);
	}
	if (rq->out_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		xrp_free(rq->out_data_allocation);
	}

	n_buffers = rq->buffer_group ? rq->buffer_group->n_buffers : 0;
	for (i = 0; i < n_buffers; ++i) {
		phys_addr_t addr;

		if (rq->buffer_group->buffer[i].buffer->type != XRP_BUFFER_TYPE_DEVICE) {
			if (rq->buffer_ptr[i].flags & XRP_DSP_BUFFER_FLAG_WRITE) {
				addr = rq->user_buffer_allocation[i]->start;
				if (!(rq->buffer_ptr[i].flags & XRP_DSP_BUFFER_FLAG_READ))
					VALGRIND_MAKE_MEM_DEFINED(p2v(addr),
								  rq->buffer_group->buffer[i].buffer->size);
				memcpy(rq->buffer_group->buffer[i].buffer->ptr, p2v(addr),
				       rq->buffer_group->buffer[i].buffer->size);
			}
			xrp_free(rq->user_buffer_allocation[i]);
		}
	}
	if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
		xrp_free(rq->buffer_allocation);
	}

	if (rq->buffer_group)
		xrp_release_buffer_group(rq->buffer_group, NULL);

	if (rq->event) {
		pthread_mutex_lock(&rq->event->mutex);
		pthread_cond_broadcast(&rq->event->cond);
		pthread_mutex_unlock(&rq->event->mutex);
		xrp_release_event(rq->event, NULL);
	}
	free(rq->user_buffer_allocation);
	free(rq);
	pthread_setcancelstate(old_state, NULL);
}

void xrp_enqueue_command(struct xrp_queue *queue,
			 const void *in_data, size_t in_data_size,
			 void *out_data, size_t out_data_size,
			 struct xrp_buffer_group *buffer_group,
			 struct xrp_event **evt,
			 enum xrp_status *status)
{
	struct xrp_device *device = queue->device;
	struct xrp_event *event = NULL;
	size_t n_buffers = buffer_group ? buffer_group->n_buffers : 0;
	size_t i;
	struct xrp_request *rq = malloc(sizeof(*rq));
	struct xrp_dsp_cmd *dsp_cmd = &rq->dsp_cmd;
	void *in_data_ptr;

	rq->in_data_size = in_data_size;
	rq->out_data = out_data;
	rq->out_data_size = out_data_size;
	rq->buffer_group = buffer_group;
	if (buffer_group)
		xrp_retain_buffer_group(buffer_group, NULL);

	if (in_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		long rc = xrp_allocate(&device->shared_pool, in_data_size,
				       0x10, &rq->in_data_allocation);
		if (rc < 0) {
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		dsp_cmd->in_data_addr = rq->in_data_allocation->start;
		in_data_ptr = p2v(rq->in_data_allocation->start);
	} else {
		in_data_ptr = &dsp_cmd->in_data;
	}
	dsp_cmd->in_data_size = in_data_size;
	memcpy(in_data_ptr, in_data, in_data_size);

	if (out_data_size > XRP_DSP_CMD_INLINE_DATA_SIZE) {
		long rc = xrp_allocate(&device->shared_pool, out_data_size,
				       0x10, &rq->out_data_allocation);
		if (rc < 0) {
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		dsp_cmd->out_data_addr = rq->out_data_allocation->start;
		rq->out_data_ptr = p2v(rq->out_data_allocation->start);
	} else {
		rq->out_data_ptr = &dsp_cmd->out_data;
	}
	dsp_cmd->out_data_size = out_data_size;

	if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
		long rc = xrp_allocate(&device->shared_pool,
				       n_buffers * sizeof(struct xrp_dsp_buffer),
				       0x10, &rq->buffer_allocation);
		if (rc < 0) {
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		dsp_cmd->buffer_addr = rq->buffer_allocation->start;
		rq->buffer_ptr = p2v(rq->buffer_allocation->start);
	} else {
		rq->buffer_ptr = dsp_cmd->buffer_data;
	}
	dsp_cmd->buffer_size = n_buffers * sizeof(struct xrp_dsp_buffer);

	rq->user_buffer_allocation = malloc(n_buffers * sizeof(void *));
	for (i = 0; i < n_buffers; ++i) {
		phys_addr_t addr;

		if (buffer_group->buffer[i].buffer->map_count > 0) {
			set_status(status, XRP_STATUS_FAILURE);
			return;

		}
		if (buffer_group->buffer[i].buffer->type == XRP_BUFFER_TYPE_DEVICE) {
			addr = buffer_group->buffer[i].buffer->xrp_allocation->start;
		} else {
			long rc = xrp_allocate(&device->shared_pool,
					       buffer_group->buffer[i].buffer->size,
					       0x10, rq->user_buffer_allocation + i);

			if (rc < 0) {
				set_status(status, XRP_STATUS_FAILURE);
				return;
			}
			addr = rq->user_buffer_allocation[i]->start;
			memcpy(p2v(addr), buffer_group->buffer[i].buffer->ptr,
			       buffer_group->buffer[i].buffer->size);
		}
		rq->buffer_ptr[i] = (struct xrp_dsp_buffer){
			.flags = buffer_group->buffer[i].access_flags,
			.size = buffer_group->buffer[i].buffer->size,
			.addr = addr,
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
		pthread_mutex_init(&event->mutex, NULL);
		pthread_cond_init(&event->cond, NULL);
		*evt = event;
		xrp_retain_event(event, NULL);
		rq->event = event;
	}
	dsp_cmd->flags = 0;
	xrp_enqueue_request(device, rq);
	set_status(status, XRP_STATUS_SUCCESS);
}

void xrp_wait(struct xrp_event *event, enum xrp_status *status)
{
	pthread_mutex_lock(&event->mutex);
	pthread_cond_wait(&event->cond, &event->mutex);
	pthread_mutex_unlock(&event->mutex);
	set_status(status, XRP_STATUS_SUCCESS);
}

void xrp_exit(void)
{
	void *exit_loc = p2v(xrp_exit_loc);
	xrp_comm_write32(exit_loc, 0xff);
}
