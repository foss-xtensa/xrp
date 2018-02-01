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
#include "../xrp-kernel/xrp_hw_simple_dsp_interface.h"
#include "xrp_private_alloc.h"

#if defined(__STDC_NO_ATOMICS__)
#warning The compiler does not support atomics, reference counting may not be thread safe
#define _Atomic
#endif

#ifdef DEBUG
#define pr_debug printf
#else
static inline int pr_debug(const char *p, ...)
{
	(void)p;
	return 0;
}
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
	uint32_t device_irq_host_offset;
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

	size_t n_buffers;
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
	struct xrp_allocation_pool *shared_pool;

	pthread_t thread;
	pthread_mutex_t request_queue_mutex;
	pthread_cond_t request_queue_cond;
	struct {
		struct xrp_request *head;
		struct xrp_request *tail;
	} request_queue;
	int exit;
	int *sync_exit;
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

struct xrp_queue {
	struct xrp_refcounted ref;
	struct xrp_device *device;
	int use_nsid;
	char nsid[XRP_NAMESPACE_ID_SIZE];
};

struct xrp_event {
	struct xrp_refcounted ref;
	struct xrp_device *device;
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

static uint32_t getprop_u32(const void *value, int offset)
{
	fdt32_t v;

	memcpy(&v, value + offset, sizeof(v));
	return fdt32_to_cpu(v);
}

static struct xrp_shmem *find_shmem_by_phys(phys_addr_t addr)
{
	int i;

	for (i = 0; i < xrp_shmem_count; ++i) {
		if (addr >= xrp_shmem[i].start &&
		    addr - xrp_shmem[i].start < xrp_shmem[i].size)
			return xrp_shmem + i;
	}
	return NULL;
}

static struct xrp_shmem *find_shmem_by_virt(const void *p)
{
	int i;

	for (i = 0; i < xrp_shmem_count; ++i) {
		size_t d = (const char *)p - (const char *)xrp_shmem[i].ptr;

		if (p >= xrp_shmem[i].ptr &&
		    d < xrp_shmem[i].size)
			return xrp_shmem + i;
	}
	return NULL;
}

static void *p2v(phys_addr_t addr)
{
	struct xrp_shmem *shmem = find_shmem_by_phys(addr);

	if (shmem) {
		return shmem->ptr + addr - shmem->start;
	} else {
		return NULL;
	}
}

static phys_addr_t v2p(const void *p)
{
	struct xrp_shmem *shmem = find_shmem_by_virt(p);

	if (shmem) {
		return shmem->start +
			(const char *)p - (const char *)shmem->ptr;
	} else {
		return 0;
	}
}

static inline void xrp_comm_write32(volatile void *addr, __u32 v)
{
	pr_debug("%s: 0x%08x, %08x\n", __func__, v2p((const void *)addr), v);
	*(volatile __u32 *)addr = v;
}

static inline __u32 xrp_comm_read32(const volatile void *addr)
{
	return *(volatile __u32 *)addr;
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
	void *device_irq = p2v(desc->io_base + desc->device_irq_host_offset);

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
	struct xrp_hw_simple_sync_data *hw_sync =
		(struct xrp_hw_simple_sync_data *)&shared_sync->hw_sync_data;

	xrp_comm_write32(&shared_sync->sync, XRP_DSP_SYNC_START);
	mb();
	xrp_send_device_irq(desc);
	do {
		__u32 v = xrp_comm_read32(&shared_sync->sync);
		if (v == XRP_DSP_SYNC_DSP_READY)
			break;
		schedule();
	} while (1);

	xrp_comm_write32(&hw_sync->device_mmio_base,
			 desc->io_base);
	xrp_comm_write32(&hw_sync->host_irq_mode,
			 irq_mode[0]);
	xrp_comm_write32(&hw_sync->host_irq_offset,
			 0);
	xrp_comm_write32(&hw_sync->host_irq_bit,
			 0);
	xrp_comm_write32(&hw_sync->device_irq_mode,
			 irq_mode[desc->device_irq_mode]);
	xrp_comm_write32(&hw_sync->device_irq_offset,
			 desc->device_irq[0]);
	xrp_comm_write32(&hw_sync->device_irq_bit,
			 desc->device_irq[1]);
	xrp_comm_write32(&hw_sync->device_irq,
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

struct of_node_match {
	const char *compatible;
	int (*init)(void *fdt, int offset,
		    struct xrp_device_description *description);
};

static int init_cdns_xrp_common(struct xrp_device_description *description)
{
	description->comm_ptr = p2v(description->comm_base);
	if (!description->comm_ptr) {
		printf("%s: shmem not found for comm area @0x%08x\n",
		       __func__, description->comm_base);
		return 0;
	}

	description->shared_ptr = p2v(description->shared_base);
	if (!description->shared_ptr) {
		printf("%s: shmem not found for shared area @0x%08x\n",
		       __func__, description->shared_base);
		return 0;
	}
	return 1;
}

static int init_cdns_xrp(void *fdt, int offset,
			 struct xrp_device_description *description)
{
	const void *reg;
	int len;

	reg = fdt_getprop(fdt, offset, "reg", &len);
	if (!reg) {
		printf("%s: %s\n", __func__, fdt_strerror(len));
		return 0;
	}
	if (len < 24) {
		printf("%s: reg property size is too small (%d)\n",
		       __func__, len);
		return 0;
	}

	*description = (struct xrp_device_description){
		.io_base = getprop_u32(reg, 0),
		.comm_base = getprop_u32(reg, 8),
		.shared_base = getprop_u32(reg, 16),
		.shared_size = getprop_u32(reg, 20),
		.hw_mutex = PTHREAD_MUTEX_INITIALIZER,
	};
	return init_cdns_xrp_common(description);
}

static int init_cdns_xrp_v1(void *fdt, int offset,
			    struct xrp_device_description *description)
{
	const void *reg;
	int len;

	reg = fdt_getprop(fdt, offset, "reg", &len);
	if (!reg) {
		printf("%s: %s\n", __func__, fdt_strerror(len));
		return 0;
	}
	if (len < 16) {
		printf("%s: reg property size is too small (%d)\n",
		       __func__, len);
		return 0;
	}

	*description = (struct xrp_device_description){
		.comm_base = getprop_u32(reg, 0),
		.shared_base = getprop_u32(reg, 0) + 4096,
		.shared_size = getprop_u32(reg, 4) - 4096,
		.io_base = getprop_u32(reg, 8),
		.hw_mutex = PTHREAD_MUTEX_INITIALIZER,
	};
	return init_cdns_xrp_common(description);
}

static int init_cdns_xrp_hw_simple_common(void *fdt, int offset,
					  struct xrp_device_description *description)
{
	const void *device_irq;
	const void *device_irq_host_offset;
	const void *device_irq_mode;
	int len;

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
			description->device_irq_mode =
				getprop_u32(device_irq_mode, 0);
			description->device_irq[0] =
				getprop_u32(device_irq, 0);
			description->device_irq[1] =
				getprop_u32(device_irq, 4);
			description->device_irq[2] =
				getprop_u32(device_irq, 8);

			device_irq_host_offset = fdt_getprop(fdt, offset,
							     "device-irq-host-offset",
							     &len);
			if (!device_irq_host_offset || len < 4) {
				description->device_irq_host_offset =
					description->device_irq[0];
				printf("%s: valid device-irq-host-offset not found, not using\n",
				       __func__);
			} else {
				description->device_irq_host_offset =
					getprop_u32(device_irq_host_offset, 0);
			}
		}
	}
	return 1;
}

static int init_cdns_xrp_hw_simple(void *fdt, int offset,
				   struct xrp_device_description *description)
{
	return init_cdns_xrp(fdt, offset, description) &&
		init_cdns_xrp_hw_simple_common(fdt, offset, description);
}

static int init_cdns_xrp_hw_simple_v1(void *fdt, int offset,
				      struct xrp_device_description *description)
{
	return init_cdns_xrp_v1(fdt, offset, description) &&
		init_cdns_xrp_hw_simple_common(fdt, offset, description);
}

static void initialize(void)
{
	int offset = -1;
	void *fdt = &dt_blob_start;
	static const struct of_node_match of_match[] = {
		{
			.compatible = "cdns,xrp",
			.init = init_cdns_xrp
		}, {
			.compatible = "cdns,xrp,v1",
			.init = init_cdns_xrp_v1
		}, {
			.compatible = "cdns,xrp-hw-simple",
			.init = init_cdns_xrp_hw_simple,
		}, {
			.compatible = "cdns,xrp-hw-simple,v1",
			.init = init_cdns_xrp_hw_simple_v1,
		}, {
			.compatible = NULL, /* last entry */
		}
	};
	const struct of_node_match *match = of_match;

	initialize_shmem();

	for (;;) {
		int ret;
		offset = fdt_node_offset_by_compatible(fdt,
						       offset,
						       match->compatible);
		if (offset < 0) {
			if (!(++match)->compatible)
				break;
			offset = -1;
			continue;
		}

		ret = match->init(fdt, offset,
				  xrp_device_description + xrp_device_count);
		if (ret == 0)
			continue;

		synchronize(xrp_device_description + xrp_device_count);
		++xrp_device_count;
	}

}

/* Device API. */

static int xrp_queue_process(struct xrp_device *device);

static void *xrp_device_thread(void *p)
{
	struct xrp_device *device = p;

	while (xrp_queue_process(device)) {
	}

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
	xrp_init_private_pool(&device->shared_pool,
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
		pthread_mutex_lock(&device->request_queue_mutex);
		device->exit = 1;
		pthread_cond_broadcast(&device->request_queue_cond);
		pthread_mutex_unlock(&device->request_queue_mutex);
		if (pthread_join(device->thread, NULL) != 0) {
			*device->sync_exit = 1;
			pthread_detach(device->thread);
		}
		pthread_mutex_lock(&device->request_queue_mutex);
		if (device->request_queue.head != NULL)
			printf("%s: releasing a device with non-empty queue\n",
			       __func__);
		pthread_mutex_unlock(&device->request_queue_mutex);
		pthread_mutex_destroy(&device->request_queue_mutex);
		pthread_cond_destroy(&device->request_queue_cond);
		xrp_free_pool(device->shared_pool);
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
		long rc = xrp_allocate(device->shared_pool, size, 0x10,
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
	set_status(status, XRP_STATUS_SUCCESS);
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
	set_status(status, XRP_STATUS_SUCCESS);
	return n_buffers;
}

void xrp_set_buffer_in_group(struct xrp_buffer_group *group,
			     size_t index,
			     struct xrp_buffer *buffer,
			     enum xrp_access_flags access_flags,
			     enum xrp_status *status)
{
	enum xrp_status s;

	xrp_retain_buffer(buffer, &s);

	if (s == XRP_STATUS_SUCCESS) {
		struct xrp_buffer *old_buffer;

		pthread_mutex_lock(&group->mutex);
		if (index < group->n_buffers) {
			old_buffer = group->buffer[index].buffer;
			group->buffer[index].buffer = buffer;
			group->buffer[index].access_flags = access_flags;
			s = XRP_STATUS_SUCCESS;
		} else {
			old_buffer = buffer;
			s = XRP_STATUS_FAILURE;
		}
		pthread_mutex_unlock(&group->mutex);
		xrp_release_buffer(old_buffer, NULL);
	}
	set_status(status, s);
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

void xrp_buffer_group_get_info(struct xrp_buffer_group *group,
			       enum xrp_buffer_group_info info, size_t idx,
			       void *out, size_t out_sz,
			       enum xrp_status *status)
{
	enum xrp_status s = XRP_STATUS_FAILURE;
	size_t sz;
	void *ptr;

	pthread_mutex_lock(&group->mutex);
	switch (info) {
	case XRP_BUFFER_GROUP_BUFFER_FLAGS_ENUM:
		if (idx >= group->n_buffers)
			goto out;
		sz = sizeof(group->buffer[idx].access_flags);
		ptr = &group->buffer[idx].access_flags;
		break;

	default:
		goto out;
	}

	if (sz == out_sz) {
		memcpy(out, ptr, sz);
		s = XRP_STATUS_SUCCESS;
	}
out:
	pthread_mutex_unlock(&group->mutex);
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
	if (nsid) {
		queue->use_nsid = 1;
		memcpy(queue->nsid, nsid, XRP_NAMESPACE_ID_SIZE);
	}
	set_status(status, XRP_STATUS_SUCCESS);

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

static int xrp_queue_process(struct xrp_device *device)
{
	struct xrp_dsp_cmd *dsp_cmd = device->description->comm_ptr;
	struct xrp_request *rq;
	size_t i;
	int exit = 0;

	device->sync_exit = &exit;
	pthread_mutex_lock(&device->request_queue_mutex);
	for (;;) {
		rq = _xrp_dequeue_request(device);
		if (rq || device->exit)
			break;
		pthread_cond_wait(&device->request_queue_cond,
				  &device->request_queue_mutex);
	}
	pthread_mutex_unlock(&device->request_queue_mutex);

	if (!rq)
		return 0;

	pthread_mutex_lock(&device->description->hw_mutex);
	memcpy(dsp_cmd, &rq->dsp_cmd, sizeof(rq->dsp_cmd));
	barrier();
	xrp_comm_write32(&dsp_cmd->flags,
			 rq->dsp_cmd.flags | XRP_DSP_CMD_FLAG_REQUEST_VALID);
	barrier();
	xrp_send_device_irq(device->description);
	do {
		barrier();
	} while ((xrp_comm_read32(&dsp_cmd->flags) &
		  (XRP_DSP_CMD_FLAG_REQUEST_VALID |
		   XRP_DSP_CMD_FLAG_RESPONSE_VALID)) !=
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

	if (rq->buffer_group)
		pthread_mutex_lock(&rq->buffer_group->mutex);

	for (i = 0; i < rq->n_buffers; ++i) {
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
	if (rq->n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
		xrp_free(rq->buffer_allocation);
	}

	if (rq->buffer_group) {
		pthread_mutex_unlock(&rq->buffer_group->mutex);
		xrp_release_buffer_group(rq->buffer_group, NULL);
	}

	if (rq->event) {
		struct xrp_event *event = rq->event;
		pthread_mutex_lock(&event->mutex);
		if (rq->dsp_cmd.flags & XRP_DSP_CMD_FLAG_RESPONSE_DELIVERY_FAIL)
			event->status = XRP_STATUS_FAILURE;
		else
			event->status = XRP_STATUS_SUCCESS;
		pthread_cond_broadcast(&event->cond);
		pthread_mutex_unlock(&event->mutex);
		xrp_release_event(event, NULL);
	}
	free(rq->user_buffer_allocation);
	free(rq);
	return !exit;
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
	size_t n_buffers;
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
		long rc = xrp_allocate(device->shared_pool, in_data_size,
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
		long rc = xrp_allocate(device->shared_pool, out_data_size,
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

	if (buffer_group)
		pthread_mutex_lock(&buffer_group->mutex);

	n_buffers = buffer_group ? buffer_group->n_buffers : 0;
	if (n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT) {
		long rc = xrp_allocate(device->shared_pool,
				       n_buffers * sizeof(struct xrp_dsp_buffer),
				       0x10, &rq->buffer_allocation);
		if (rc < 0) {
			pthread_mutex_unlock(&buffer_group->mutex);
			set_status(status, XRP_STATUS_FAILURE);
			return;
		}
		dsp_cmd->buffer_addr = rq->buffer_allocation->start;
		rq->buffer_ptr = p2v(rq->buffer_allocation->start);
	} else {
		rq->buffer_ptr = dsp_cmd->buffer_data;
	}
	dsp_cmd->buffer_size = n_buffers * sizeof(struct xrp_dsp_buffer);

	rq->n_buffers = n_buffers;
	rq->user_buffer_allocation = malloc(n_buffers * sizeof(void *));
	for (i = 0; i < n_buffers; ++i) {
		phys_addr_t addr;

		if (buffer_group->buffer[i].buffer->map_count > 0) {
			pthread_mutex_unlock(&buffer_group->mutex);
			set_status(status, XRP_STATUS_FAILURE);
			return;

		}
		if (buffer_group->buffer[i].buffer->type == XRP_BUFFER_TYPE_DEVICE) {
			addr = buffer_group->buffer[i].buffer->xrp_allocation->start;
		} else {
			long rc = xrp_allocate(device->shared_pool,
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

	if (buffer_group)
		pthread_mutex_unlock(&buffer_group->mutex);

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
		event->status = XRP_STATUS_PENDING;
		*evt = event;
		xrp_retain_event(event, NULL);
		rq->event = event;
	}
	dsp_cmd->flags = (queue->use_nsid ? XRP_DSP_CMD_FLAG_REQUEST_NSID : 0);
	if (queue->use_nsid) {
		memcpy(dsp_cmd->nsid, queue->nsid, sizeof(dsp_cmd->nsid));
	}
	xrp_enqueue_request(device, rq);
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

void xrp_exit(void)
{
	void *exit_loc = p2v(xrp_exit_loc);
	xrp_comm_write32(exit_loc, 0xff);
}
