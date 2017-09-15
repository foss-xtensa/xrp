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
#include <xtensa/tie/xt_sync.h>
#include <xtensa/xtruntime.h>

#include "xrp_api.h"
#include "xrp_dsp_hw.h"

static enum xrp_status run_command_loop(void)
{
	enum xrp_status status;
	struct xrp_device *device = xrp_open_device(0, &status);

	if (status != XRP_STATUS_SUCCESS)
		return status;

	for (;;) {
		status = xrp_device_dispatch(device);
		if (status == XRP_STATUS_PENDING)
			xrp_hw_wait_device_irq();
		else if (status != XRP_STATUS_SUCCESS)
			return status;
	}
}

void xrp_user_initialize(enum xrp_status *status) __attribute__((weak));
void xrp_user_initialize(enum xrp_status *status)
{
	*status = XRP_STATUS_SUCCESS;
}

int main()
{
	enum xrp_status status = XRP_STATUS_SUCCESS;

	xrp_user_initialize(&status);

	if (status != XRP_STATUS_SUCCESS)
		return status;
	return run_command_loop();
}
