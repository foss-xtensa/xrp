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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtensa/corebits.h>
#include <xtensa/xtruntime.h>
#include "xrp_api.h"

static void hang(void) __attribute__((noreturn));
static void hang(void)
{
	for (;;);
}

void abort(void)
{
	fprintf(stderr, "abort() is called; halting\n");
	hang();
}

static void exception(void)
{
	unsigned long exccause, excvaddr, ps, epc1;

	__asm__ volatile ("rsr %0, exccause\n\t"
			  "rsr %1, excvaddr\n\t"
			  "rsr %2, ps\n\t"
			  "rsr %3, epc1"
			  : "=a"(exccause), "=a"(excvaddr),
			    "=a"(ps), "=a"(epc1));

	fprintf(stderr, "%s: EXCCAUSE = %ld, EXCVADDR = 0x%08lx, PS = 0x%08lx, EPC1 = 0x%08lx\n",
		__func__, exccause, excvaddr, ps, epc1);
	hang();
}

static void register_exception_handlers(void)
{
	static const int cause[] = {
		EXCCAUSE_ILLEGAL,
		EXCCAUSE_INSTR_ERROR,
		EXCCAUSE_LOAD_STORE_ERROR,
		EXCCAUSE_DIVIDE_BY_ZERO,
		EXCCAUSE_PRIVILEGED,
		EXCCAUSE_UNALIGNED,
		EXCCAUSE_INSTR_DATA_ERROR,
		EXCCAUSE_LOAD_STORE_DATA_ERROR,
		EXCCAUSE_INSTR_ADDR_ERROR,
		EXCCAUSE_LOAD_STORE_ADDR_ERROR,
		EXCCAUSE_ITLB_MISS,
		EXCCAUSE_ITLB_MULTIHIT,
		EXCCAUSE_INSTR_RING,
		EXCCAUSE_INSTR_PROHIBITED,
		EXCCAUSE_DTLB_MISS,
		EXCCAUSE_DTLB_MULTIHIT,
		EXCCAUSE_LOAD_STORE_RING,
		EXCCAUSE_LOAD_PROHIBITED,
		EXCCAUSE_STORE_PROHIBITED,
	};
	unsigned i;

	for (i = 0; i < sizeof(cause) / sizeof(cause[0]); ++i) {
		_xtos_set_exception_handler(cause[i], exception);
	}
}

void xrp_user_initialize(enum xrp_status *status)
{
	printf("%s\n", __func__);
	register_exception_handlers();
	atexit(hang);
	if (status != NULL)
		*status = XRP_STATUS_SUCCESS;
}

void xrp_run_command(const void *in_data, size_t in_data_size,
		     void *out_data, size_t out_data_size,
		     struct xrp_buffer_group *buffer_group,
		     enum xrp_status *status)
{
	size_t i;
	uint32_t sz = 0;

	printf("%s, in_data_size = %zu, out_data_size = %zu\n",
	       __func__, in_data_size, out_data_size);

	for (i = 0; i < in_data_size; ++i) {
		if (i < out_data_size)
			((uint8_t *)out_data)[i] =
				((uint8_t *)in_data)[i] + i;
	}

	if (in_data_size >= sizeof(sz))
		memcpy(&sz, in_data, sizeof(sz));

	for (i = 0; sz; i += 2) {
		struct xrp_buffer *sbuf = xrp_get_buffer_from_group(buffer_group, i, NULL);
		struct xrp_buffer *dbuf = xrp_get_buffer_from_group(buffer_group, i + 1, NULL);
		void *src, *dst;

		if (!sbuf || !dbuf)
			break;

		src = xrp_map_buffer(sbuf, 0, sz, XRP_READ, NULL);
		dst = xrp_map_buffer(dbuf, 0, sz, XRP_WRITE, NULL);

		if (!src || !dst) {
			xrp_release_buffer(sbuf, NULL);
			xrp_release_buffer(dbuf, NULL);
			break;
		}

		printf("%s: copy %d bytes from %p to %p\n",
		       __func__, sz, src, dst);
		memcpy(dst, src, sz);
		xrp_unmap_buffer(sbuf, src, NULL);
		xrp_unmap_buffer(dbuf, dst, NULL);
		xrp_release_buffer(sbuf, NULL);
		xrp_release_buffer(dbuf, NULL);
	}
	if (status != NULL)
		*status = XRP_STATUS_SUCCESS;
}
