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
#if HAVE_THREADS_XOS
#include <xtensa/xos.h>
#endif
#include "xrp_api.h"
#include "xrp_dsp_hw.h"
#include "xrp_dsp_user.h"

static void hang(void) __attribute__((noreturn));
static void hang(void)
{
	for (;;)
		xrp_hw_panic();
}

void abort(void)
{
	fprintf(stderr, "abort() is called; halting\n");
	hang();
}


#if HAVE_THREADS_XOS
static void xos_exception(XosExcFrame *frame)
{
	fprintf(stderr, "%s: EXCCAUSE = %ld/0x%lx, EXCVADDR = 0x%08lx, PS = 0x%08lx, EPC1 = 0x%08lx\n",
		__func__,
		(unsigned long)frame->exccause, (unsigned long)frame->exccause,
		(unsigned long)frame->excvaddr,
		(unsigned long)frame->ps, (unsigned long)frame->pc);
	hang();
}
#else
#if HAVE_XTOS_SET_EXCEPTION_HANDLER
static void xtos_exception(void *arg)
{
#if XCHAL_HAVE_XEA3
	ExcFrame *frame = arg;
#else
	UserFrame *frame = arg;
#endif

	fprintf(stderr, "%s: EXCCAUSE = %ld/0x%lx, PS = 0x%08lx, EPC1 = 0x%08lx\n",
		__func__,
		(unsigned long)frame->exccause,
		(unsigned long)frame->exccause,
		(unsigned long)frame->ps, (unsigned long)frame->pc);
	hang();
}
#else
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
#endif
#endif

static void register_exception_handler(uint32_t cause)
{
#if HAVE_THREADS_XOS
	xos_register_exception_handler(cause, xos_exception);
#else
#if HAVE_XTOS_SET_EXCEPTION_HANDLER
	xtos_set_exception_handler(cause, xtos_exception, NULL);
#else
	_xtos_set_exception_handler(cause, exception);
#endif
#endif
}

#if XCHAL_HAVE_XEA3
static void register_exception_handlers(void)
{
	static const int cause[] = {
		EXCCAUSE_INSTRUCTION,
		EXCCAUSE_ADDRESS,
		EXCCAUSE_EXTERNAL,
		EXCCAUSE_HARDWARE,
		EXCCAUSE_MEMORY,
		EXCCAUSE_CP_DISABLED,
	};

	unsigned i;

	for (i = 0; i < sizeof(cause) / sizeof(cause[0]); ++i)
		register_exception_handler(cause[i]);
}
#else
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

	for (i = 0; i < sizeof(cause) / sizeof(cause[0]); ++i)
		register_exception_handler(cause[i]);
}
#endif

int main(void)
{
	enum xrp_status status;
#if HAVE_THREADS_XOS
	static uint32_t main_priority[] = {0};

	register_exception_handlers();
	xrp_hw_init();
	status = xrp_user_create_queues(1, main_priority);
	if (status != XRP_STATUS_SUCCESS) {
		fprintf(stderr, "Initial xrp_user_create_queue failed\n");
		abort();
	}
	xos_start(0);
#else
	struct xrp_device *device;

	register_exception_handlers();
	xrp_hw_init();
	device = xrp_open_device(0, &status);
	if (status != XRP_STATUS_SUCCESS) {
		fprintf(stderr, "xrp_open_device failed\n");
		abort();
	}

	for (;;) {
		status = xrp_device_dispatch(device);
		if (status == XRP_STATUS_PENDING)
			xrp_hw_wait_device_irq();
	}
#endif
	return 0;
}
