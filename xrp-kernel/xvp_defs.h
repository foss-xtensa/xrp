/*
 * XVP - Linux device driver for APK.
 * $Id: xvp.h 4 2015-10-14 20:58:06Z sugawara $
 *
 * Copyright (c) 2015 Cadence Design Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Further, this software is distributed without any warranty that it
 * is free of the rightful claim of any third person regarding
 * infringement  or the like.  Any license provided herein, whether
 * implied or otherwise, applies only to this software file.  Patent
 * licenses, if any, provided herein do not apply to combinations of
 * this program with other software, or any other product whatsoever.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 */

#ifndef _XVP_DEFS_H_
#define _XVP_DEFS_H_

/*
 * IOCTL requests
 *   S: Set through a ptr
 *   T: Tell directly with the argument value
 *   G: Get reply by setting throug a ptr
 *   Q: Query reponse is the return value
 *   X: eXchange = switch G and S (atomic)
 *   H: sHift = switch T and Q (atomic)
 */
#define XVP_IOCTL_MAGIC 'x'
#define XVP_IOCTLX_ALLOC        _IO(XVP_IOCTL_MAGIC,    1)
#define XVP_IOCTLS_FREE         _IO(XVP_IOCTL_MAGIC,    2)
#define XVP_IOCTLQ_GET_PADDR    _IOR(XVP_IOCTL_MAGIC,   3, int)
#define XVP_IOCTLQ_GET_VADDR    _IOR(XVP_IOCTL_MAGIC,   4, int)
#define XVP_IOCTLS_SUBMIT_SYNC	_IO(XVP_IOCTL_MAGIC,	5)
#define XVP_IOCTL_INVALIDATE_CACHE	_IO(XVP_IOCTL_MAGIC,	6)

#define XVP_IOCTL_MAXNR         14

struct xvp_ioctlx_alloc {
	__u32 size;
	__u32 align;
	__u32 type;
	__u32 virt_addr;
	__u32 phys_addr;
};

struct xvp_ioctlq_get_paddr {
	__u32 num_addr;
	__u32 addrs;
	__u32 sizes;
};

struct xvp_ioctl_invalidate_cache {
	__u32 num_addr;
	__u32 addrs;
	__u32 sizes;
};

struct xvp_ioctls_submit {
	__u32 cmd;
	__u32 addr;
	__u32 size;
	__u32 status;
};

#endif /* _XVP_DEFS_H_ */
