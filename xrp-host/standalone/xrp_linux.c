/*
 * Copyright (c) 2016 - 2018 Cadence Design Systems Inc.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "xrp_types.h"
#include "xrp_host_common.h"
#include "xrp_host_impl.h"
#include "xrp_private_alloc.h"
#include "xrp_host.h"

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
static phys_addr_t xrp_exit_loc;

/* Helpers */

static uint32_t getprop_u32(const void *value, int offset)
{
	fdt32_t v;

	memcpy(&v, value + offset, sizeof(v));
	return fdt32_to_cpu(v);
}

static inline void xrp_comm_write32(volatile void *addr, __u32 v)
{
	*(volatile __u32 *)addr = v;
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

void *p2v(phys_addr_t addr)
{
	struct xrp_shmem *shmem = find_shmem_by_phys(addr);

	if (shmem) {
		return shmem->ptr + addr - shmem->start;
	} else {
		return NULL;
	}
}

phys_addr_t v2p(const void *p)
{
	struct xrp_shmem *shmem = find_shmem_by_virt(p);

	if (shmem) {
		return shmem->start +
			(const char *)p - (const char *)shmem->ptr;
	} else {
		return 0;
	}
}

void xrp_initialize_shmem(void)
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

void xrp_exit(void)
{
	void *exit_loc = p2v(xrp_exit_loc);
	xrp_comm_write32(exit_loc, 0xff);
}
