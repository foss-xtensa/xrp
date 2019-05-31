/*
 * Copyright (c) 2018 Cadence Design Systems Inc.
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

#include "xrp_types.h"
#include "xrp_debug.h"
#include "xrp_dsp_hw.h"
#include "xrp_dsp_interrupt.h"
#include "xrp_hw_hikey960_dsp_interface.h"
#include "xrp_rb_file.h"

enum xrp_irq_mode {
	XRP_IRQ_NONE,
	XRP_IRQ_LEVEL,
	XRP_IRQ_EDGE,
};
static enum xrp_irq_mode host_irq_mode;
static enum xrp_irq_mode device_irq_mode;
static uint32_t device_irq;

struct ipcm_struct {
	uint32_t source;
	uint32_t dset;
	uint32_t dclear;
	uint32_t dstatus;
	uint32_t mode;
	uint32_t imask;
	uint32_t iclear;
	uint32_t send;
	uint32_t dr[8];
};

struct ipcm_int_struct {
	uint32_t mis;
	uint32_t ris;
};

static volatile struct xrp_hw_hikey960_panic *panic = (volatile void *)0x8b300000;
static volatile struct ipcm_struct *ipcm = (volatile struct ipcm_struct *)0xe896b000;
static volatile struct ipcm_int_struct *ipcm_int = (volatile struct ipcm_int_struct *)0xe896b800;

static inline uint32_t get_ccount(void)
{
	uint32_t ccount;

	asm volatile ("rsr.ccount %0" : "=a" (ccount) :: "memory");
	return ccount;
}

static void ipcm_send(void)
{
	volatile struct ipcm_struct *mb = ipcm + 2;

	mb->iclear = 0x10;
	if (!(mb->mode & 0x10)) {
	}
	mb->source = 0x10;
	mb->dclear = ~0;
	mb->dset = 0x0;
	mb->imask = ~0x11;
	mb->mode = 0x1;
	mb->dr[0] = 0x1;
	mb->send = 0x10;
}

static void ipcm_ack(void)
{
	ipcm[18].iclear = ~ipcm[18].imask & 0x10;
}

static void xrp_irq_handler(void)
{
	panic->ccount = get_ccount();
	pr_debug("%s\n", __func__);
	if (device_irq_mode == XRP_IRQ_LEVEL) {
		ipcm_ack();
	}
}

void xrp_hw_send_host_irq(void)
{
	switch (host_irq_mode) {
	case XRP_IRQ_EDGE:
	case XRP_IRQ_LEVEL:
		ipcm_send();
		break;
	default:
		break;
	}
}

void xrp_hw_wait_device_irq(void)
{
	unsigned old_intlevel;

	panic->ccount = get_ccount();

	if (device_irq_mode == XRP_IRQ_NONE)
		return;

	pr_debug("%s: waiting for device IRQ...\n", __func__);
	old_intlevel = XTOS_SET_INTLEVEL(XCHAL_NUM_INTLEVELS - 1);
	xrp_interrupt_enable(device_irq);
	XT_WAITI(0);
	xrp_interrupt_disable(device_irq);
	XTOS_RESTORE_INTLEVEL(old_intlevel);
}

void xrp_hw_set_sync_data(void *p)
{
	static const enum xrp_irq_mode irq_mode[] = {
		[XRP_DSP_SYNC_IRQ_MODE_NONE] = XRP_IRQ_NONE,
		[XRP_DSP_SYNC_IRQ_MODE_LEVEL] = XRP_IRQ_LEVEL,
		[XRP_DSP_SYNC_IRQ_MODE_EDGE] = XRP_IRQ_EDGE,
	};
	struct xrp_hw_hikey960_sync_data *hw_sync = p;

	if (hw_sync->device_irq_mode < sizeof(irq_mode) / sizeof(*irq_mode)) {
		device_irq_mode = irq_mode[hw_sync->device_irq_mode];
		device_irq = hw_sync->device_irq;
		pr_debug("%s: device_irq_mode = %d, device_irq = %d\n",
			 __func__, device_irq_mode, device_irq);
	} else {
		device_irq_mode = XRP_IRQ_NONE;
	}

	if (hw_sync->host_irq_mode < sizeof(irq_mode) / sizeof(*irq_mode)) {
		host_irq_mode = irq_mode[hw_sync->host_irq_mode];
		pr_debug("%s: host_irq_mode = %d\n",
			 __func__, host_irq_mode);
	} else {
		host_irq_mode = XRP_IRQ_NONE;
	}

	if (device_irq_mode != XRP_IRQ_NONE) {
		xrp_interrupt_disable(device_irq);
		xrp_set_interrupt_handler(device_irq, xrp_irq_handler);
	}
}

void xrp_hw_panic(void)
{
	panic->panic = 0xdeadbabe;
	panic->ccount = get_ccount();
}

void outbyte(int c)
{
	char b = (unsigned char)c;

	xrp_rb_write((void *)&panic->rb, &b, 1);
}

int inbyte(void)
{
	return -1;
}

void xrp_hw_init(void)
{
	panic->panic = 0;
	panic->ccount = 0;
	panic->rb.read = 0;
	panic->rb.write = 0;
	panic->rb.size = 0x1000 - sizeof(struct xrp_hw_hikey960_panic);
}
