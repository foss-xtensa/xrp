#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtensa/corebits.h>
#include <xtensa/xtruntime.h>
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

static void register_exception_handler(uint32_t cause)
{
	xtos_set_exception_handler(cause, xtos_exception, NULL);
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

void xrp_run_command(const void *in_data, size_t in_data_size,
         void *out_data, size_t out_data_size,
         struct xrp_buffer_group *buffer_group,
         enum xrp_status *status)
{
  (void)in_data;
  (void)in_data_size;
  (void)out_data;
  (void)out_data_size;
  (void)buffer_group;

  *(int *)out_data = *(int *)in_data;

  if (status)
    *status = XRP_STATUS_SUCCESS;
}

int main(void)
{
	enum xrp_status status;
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

	return 0;
}
