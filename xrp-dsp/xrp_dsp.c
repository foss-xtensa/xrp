#include <stdint.h>
#include <stdio.h>
#include <xtensa/tie/xt_interrupt.h>
#include <xtensa/tie/xt_sync.h>
#include <xtensa/xtruntime.h>

#include "xrp_api.h"

typedef uint8_t __u8;
typedef uint32_t __u32;
#include "xrp_kernel_dsp_interface.h"

#ifdef DEBUG
#define dprintf printf
#else
static inline int dprintf(const char *p, ...)
{
	(void)p;
	return 0;
}
#endif

void *xrp_dsp_comm_base = (void *)XRP_DSP_COMM_BASE_MAGIC;

static int use_irq;
static unsigned host_irq_num;
static unsigned dsp_irq_num;

static void *MMIO = (void *)0xf1000000;

#define mmio_dsp_irq(n) ((volatile uint32_t *)MMIO + 0x0014/4 + (n))
#define mmio_host_irq(n)((volatile uint32_t *)MMIO + 0x1014/4 + (n))

/* DSP side XRP API implementation */

struct xrp_refcounted {
	unsigned long count;
};

struct xrp_buffer {
	struct xrp_refcounted ref;
	void *ptr;
	size_t size;
	unsigned long map_count;
	enum xrp_access_flags allowed_access;
	enum xrp_access_flags map_flags;
};

struct xrp_buffer_group {
	struct xrp_refcounted ref;
	size_t n_buffers;
	struct xrp_buffer *buffer;
};


static inline void set_status(enum xrp_status *status, enum xrp_status v)
{
	if (status)
		*status = v;
}

static enum xrp_status retain_refcounted(struct xrp_refcounted *ref)
{
	if (ref) {
		++ref->count;
		return XRP_STATUS_SUCCESS;
	}
	return XRP_STATUS_FAILURE;
}

static enum xrp_status release_refcounted(struct xrp_refcounted *ref)
{
	if (ref) {
		if (ref->count-- > 0)
			return XRP_STATUS_SUCCESS;
	}
	return XRP_STATUS_FAILURE;
}

struct xrp_buffer *xrp_create_buffer(struct xrp_device *device,
				     size_t size, void *host_ptr,
				     enum xrp_status *status)
{
	(void)device;
	(void)size;
	(void)host_ptr;
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}

void xrp_retain_buffer(struct xrp_buffer *buffer, enum xrp_status *status)
{
	set_status(status, retain_refcounted(&buffer->ref));
}

void xrp_release_buffer(struct xrp_buffer *buffer, enum xrp_status *status)
{
	set_status(status, release_refcounted(&buffer->ref));
}

void *xrp_map_buffer(struct xrp_buffer *buffer, size_t offset, size_t size,
		     enum xrp_access_flags map_flags, enum xrp_status *status)
{
	if (offset <= buffer->size &&
	    size <= buffer->size - offset &&
	    (buffer->allowed_access & map_flags) == map_flags) {
		retain_refcounted(&buffer->ref);
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
		release_refcounted(&buffer->ref);
		set_status(status, XRP_STATUS_SUCCESS);
	} else {
		set_status(status, XRP_STATUS_FAILURE);
	}
}

struct xrp_buffer_group *xrp_create_buffer_group(enum xrp_status *status)
{
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}

void xrp_retain_buffer_group(struct xrp_buffer_group *group,
			     enum xrp_status *status)
{
	set_status(status, retain_refcounted(&group->ref));
}

void xrp_release_buffer_group(struct xrp_buffer_group *group,
			      enum xrp_status *status)
{
	set_status(status, release_refcounted(&group->ref));
}

size_t xrp_add_buffer_to_group(struct xrp_buffer_group *group,
			       struct xrp_buffer *buffer,
			       enum xrp_access_flags access_flags,
			       enum xrp_status *status)
{
	(void)group;
	(void)buffer;
	(void)access_flags;
	set_status(status, XRP_STATUS_FAILURE);
	return -1;
}

struct xrp_buffer *xrp_get_buffer_from_group(struct xrp_buffer_group *group,
					     size_t idx,
					     enum xrp_status *status)
{
	if (idx < group->n_buffers) {
		set_status(status, XRP_STATUS_SUCCESS);
		xrp_retain_buffer(group->buffer + idx, NULL);
		return group->buffer + idx;
	}
	set_status(status, XRP_STATUS_FAILURE);
	return NULL;
}

/* DSP side request handling */

static void xrp_irq_handler(void)
{
	XT_S32RI(0, mmio_dsp_irq(dsp_irq_num), 0);
}

static void do_handshake(struct xrp_dsp_sync *shared_sync)
{
	uint32_t v;

start:
	while (XT_L32AI(&shared_sync->ping, 0)) {
	}

	do {
		v = XT_L32AI(&shared_sync->pong, 0);
		if (XRP_DSP_SYNC_MODE(v) != XRP_DSP_SYNC_MODE_IDLE)
			break;
		if (XT_L32AI(&shared_sync->ping, 0))
			goto start;
	} while (XRP_DSP_SYNC_MODE(v) == XRP_DSP_SYNC_MODE_IDLE);

	XT_S32RI(0, &shared_sync->pong, 0);

	use_irq = XRP_DSP_SYNC_MODE(v) == XRP_DSP_SYNC_MODE_IRQ;
	host_irq_num = XRP_DSP_SYNC_HOST_IRQ_NUM(v);
	dsp_irq_num = XRP_DSP_SYNC_DSP_IRQ_NUM(v);

	dprintf("%s: use_irq = %d, host_irq_num = %d, dsp_irq_num = %d\n",
		__func__, use_irq, host_irq_num, dsp_irq_num);
	if (use_irq) {
		XT_S32RI(1, mmio_host_irq(host_irq_num), 0);
		_xtos_ints_off(1u << dsp_irq_num);
		_xtos_set_interrupt_handler(dsp_irq_num, xrp_irq_handler);
		_xtos_dispatch_level1_interrupts();
	}

	while (XT_L32AI(&shared_sync->ping, 0) != XRP_DSP_SYNC_POST_SYNC) {
		if (XT_L32AI(&shared_sync->pong, 0) != 0)
			goto start;
	}
}

static void wait_for_request(struct xrp_dsp_cmd *dsp_cmd)
{
	uint32_t flags;

	if (use_irq) {
		unsigned level = XTOS_SET_INTLEVEL(15);

		for (;;) {
			XT_S32RI(0, mmio_dsp_irq(dsp_irq_num), 0);

			flags = XT_L32AI(&dsp_cmd->flags, 0);
			if ((flags & (XRP_DSP_CMD_FLAG_REQUEST_VALID |
				      XRP_DSP_CMD_FLAG_RESPONSE_VALID)) ==
			    XRP_DSP_CMD_FLAG_REQUEST_VALID)
				break;

			_xtos_ints_on(1u << dsp_irq_num);
			XT_WAITI(0);
			XTOS_SET_INTLEVEL(15);
			_xtos_ints_off(1u << dsp_irq_num);
		}
		XTOS_RESTORE_INTLEVEL(level);
	} else {
		for (;;) {
			flags = XT_L32AI(&dsp_cmd->flags, 0);
			if ((flags & (XRP_DSP_CMD_FLAG_REQUEST_VALID |
				      XRP_DSP_CMD_FLAG_RESPONSE_VALID)) ==
			    XRP_DSP_CMD_FLAG_REQUEST_VALID)
				break;
		}
	}
}

static void complete_request(struct xrp_dsp_cmd *dsp_cmd)
{
	uint32_t flags = dsp_cmd->flags | XRP_DSP_CMD_FLAG_RESPONSE_VALID;

	XT_S32RI(flags, &dsp_cmd->flags, 0);
	if (use_irq) {
		XT_S32RI(1, mmio_host_irq(host_irq_num), 0);
	}
}

static enum xrp_access_flags dsp_buffer_allowed_access(__u32 flags)
{
	return flags == XRP_DSP_BUFFER_FLAG_READ ?
		XRP_READ : XRP_READ_WRITE;
}

static enum xrp_status process_command(struct xrp_dsp_cmd *dsp_cmd)
{
	enum xrp_status status;
	size_t n_buffers = dsp_cmd->buffer_size / sizeof(struct xrp_dsp_buffer);
	struct xrp_dsp_buffer *dsp_buffer =
		n_buffers > XRP_DSP_CMD_INLINE_BUFFER_COUNT ?
		(void *)dsp_cmd->buffer_addr : &dsp_cmd->buffer_data;
	struct xrp_buffer_group buffer_group;
	struct xrp_buffer buffer[n_buffers]; /* TODO */
	size_t i;

	/* Create buffers from incoming buffer data, put them to group.
	 * Passed flags add some restrictions to possible buffer mapping
	 * modes:
	 * R only allows R
	 * W and RW allow R, W or RW
	 * (actually W only allows W and RW, but that's hard to express and
	 * is not particularly useful)
	 */
	for (i = 0; i < n_buffers; ++i) {
		buffer[i] = (struct xrp_buffer){
			.allowed_access =
				dsp_buffer_allowed_access(dsp_buffer[i].flags),
			.ptr = (void *)dsp_buffer[i].addr,
			.size = dsp_buffer[i].size,
		};
	}

	buffer_group = (struct xrp_buffer_group){
		.n_buffers = n_buffers,
		.buffer = buffer,
	};

	xrp_run_command(dsp_cmd->in_data_size > sizeof(dsp_cmd->in_data) ?
			(void *)dsp_cmd->in_data_addr : dsp_cmd->in_data,
			dsp_cmd->in_data_size,
			dsp_cmd->out_data_size > sizeof(dsp_cmd->out_data) ?
			(void *)dsp_cmd->out_data_addr : dsp_cmd->out_data,
			dsp_cmd->out_data_size,
			&buffer_group,
			&status);

	/*
	 * update flags in the buffer data: what access actually took place,
	 * to update caches on the host side.
	 */
	for (i = 0; i < n_buffers; ++i) {
		__u32 flags = 0;

		if (buffer[i].map_flags & XRP_READ)
			flags |= XRP_DSP_BUFFER_FLAG_READ;
		if (buffer[i].map_flags & XRP_WRITE)
			flags |= XRP_DSP_BUFFER_FLAG_WRITE;

		dprintf("%s: dsp_buffer[%d].flags = %d\n", __func__, i, flags);
		dsp_buffer[i].flags = flags;

		if (buffer[i].ref.count) {
			dprintf("%s: refcount leak on buffer %d\n",
				__func__, i);
		}
		if (buffer[i].map_count) {
			dprintf("%s: map_count leak on buffer %d\n",
				__func__, i);
		}
	}
	if (buffer_group.ref.count) {
		dprintf("%s: refcount leak on buffer group\n", __func__);
	}

	complete_request(dsp_cmd);
	return status;
}


static enum xrp_status run_command_loop(void)
{
	do_handshake(xrp_dsp_comm_base);

	for (;;) {
		enum xrp_status status = XRP_STATUS_SUCCESS;

		wait_for_request(xrp_dsp_comm_base);
		status = process_command(xrp_dsp_comm_base);

		if (status != XRP_STATUS_SUCCESS)
			return status;
	}
}

void xrp_user_initialize(enum xrp_status *status) __attribute__((weak));
void xrp_user_initialize(enum xrp_status *status)
{
	set_status(status, XRP_STATUS_SUCCESS);
}

int main()
{
	enum xrp_status status = XRP_STATUS_SUCCESS;

	xrp_user_initialize(&status);

	if (status != XRP_STATUS_SUCCESS)
		return status;
	return run_command_loop();
}
