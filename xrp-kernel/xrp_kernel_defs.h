#ifndef _XRP_KERNEL_DEFS_H
#define _XRP_KERNEL_DEFS_H

#define XRP_IOCTL_MAGIC 'r'
#define XRP_IOCTL_ALLOC		_IO(XRP_IOCTL_MAGIC, 1)
#define XRP_IOCTL_FREE		_IO(XRP_IOCTL_MAGIC, 2)
#define XRP_IOCTL_QUEUE		_IO(XRP_IOCTL_MAGIC, 3)
#define XRP_IOCTL_WAIT		_IO(XRP_IOCTL_MAGIC, 4)

struct xrp_ioctl_alloc {
	__u32 size;
	__u32 align;
	__u64 addr;
};

struct xrp_ioctl_buffer {
	__u32 flags;
	__u32 size;
	__u64 addr;
};

struct xrp_ioctl_queue {
	__u32 flags;
	__u32 in_data_size;
	__u32 out_data_size;
	__u32 buffer_size;
	__u64 in_data_addr;
	__u64 out_data_addr;
	__u64 buffer_addr;
};

struct xrp_ioctl_wait {
	__u32 cookie;
};

#endif
