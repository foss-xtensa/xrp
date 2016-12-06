#ifndef _XRP_KERNEL_DSP_INTERFACE_H
#define _XRP_KERNEL_DSP_INTERFACE_H

#ifndef XRP_DSP_COMM_BASE_MAGIC
#define XRP_DSP_COMM_BASE_MAGIC		0x20161006
#endif

enum {
	XRP_DSP_SYNC_IDLE = 0,
	XRP_DSP_SYNC_START = 0x100,
	XRP_DSP_SYNC_DSP_READY = 0x200,
	XRP_DSP_SYNC_HOST_TO_DSP = 0x1,
	XRP_DSP_SYNC_DSP_TO_HOST = 0x3,
};

enum {
	XRP_DSP_SYNC_IRQ_MODE_NONE = 0x0,
	XRP_DSP_SYNC_IRQ_MODE_LEVEL = 0x1,
	XRP_DSP_SYNC_IRQ_MODE_EDGE = 0x2,
};

struct xrp_dsp_sync {
	__u32 sync;
	__u32 device_mmio_base;
	__u32 host_irq_mode;
	__u32 host_irq_offset;
	__u32 host_irq_bit;
	__u32 device_irq_mode;
	__u32 device_irq_offset;
	__u32 device_irq_bit;
	__u32 device_irq;
};

enum {
	XRP_DSP_BUFFER_FLAG_READ = 0x1,
	XRP_DSP_BUFFER_FLAG_WRITE = 0x2,
};

struct xrp_dsp_buffer {
	/*
	 * When submitted to DSP: types of access allowed
	 * When returned to host: actual access performed
	 */
	__u32 flags;
	__u32 size;
	__u32 addr;
};

enum {
	XRP_DSP_CMD_FLAG_REQUEST_VALID = 0x00000001,
	XRP_DSP_CMD_FLAG_RESPONSE_VALID = 0x00000002,
};

#define XRP_DSP_CMD_INLINE_DATA_SIZE 16
#define XRP_DSP_CMD_INLINE_BUFFER_COUNT 1

struct xrp_dsp_cmd {
	__u32 flags;
	__u32 in_data_size;
	__u32 out_data_size;
	__u32 buffer_size;
	union {
		__u32 in_data_addr;
		__u8 in_data[XRP_DSP_CMD_INLINE_DATA_SIZE];
	};
	union {
		__u32 out_data_addr;
		__u8 out_data[XRP_DSP_CMD_INLINE_DATA_SIZE];
	};
	union {
		__u32 buffer_addr;
		struct xrp_dsp_buffer buffer_data[XRP_DSP_CMD_INLINE_BUFFER_COUNT];
		__u8 buffer_alignment[XRP_DSP_CMD_INLINE_DATA_SIZE];
	};
};

#endif
