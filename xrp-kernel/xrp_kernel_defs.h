#ifndef _XRP_KERNEL_DEFS_H
#define _XRP_KERNEL_DEFS_H

#define XRP_IOCTL_MAGIC 'r'
#define XRP_IOCTL_ALLOC		_IO(XRP_IOCTL_MAGIC, 1)
#define XRP_IOCTL_FREE		_IO(XRP_IOCTL_MAGIC, 2)
#define XRP_IOCTL_QUEUE		_IO(XRP_IOCTL_MAGIC, 3)

struct xrp_ioctl_alloc {
	__u32 size;
	__u32 align;
	__u64 addr;
};

enum {
	XRP_FLAG_READ = 0x1,
	XRP_FLAG_WRITE = 0x2,
	XRP_FLAG_READ_WRITE = 0x3,
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

#endif
