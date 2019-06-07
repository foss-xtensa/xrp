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

#ifndef XRP_DSP_INTERRUPT_H
#define XRP_DSP_INTERRUPT_H

#include <xtensa/config/core.h>
#if XCHAL_HAVE_INTERRUPTS
#include <xtensa/tie/xt_interrupt.h>
#include <xtensa/xtruntime.h>

#ifdef HAVE_XTOS_SET_INTERRUPT_HANDLER
static inline int32_t xrp_set_interrupt_handler(uint32_t intnum,
						void (*fn)(void))
{
	return xtos_set_interrupt_handler(intnum, (void (*)(void *))fn,
					  NULL, NULL);
}
#else
static inline int32_t xrp_set_interrupt_handler(uint32_t intnum,
						void (*fn)(void))
{
	_xtos_set_interrupt_handler(intnum, fn);
	return 0;
}
#endif

#ifdef HAVE_XTOS_INTERRUPT_ENABLE
static inline void xrp_interrupt_enable(uint32_t intnum)
{
	xtos_interrupt_enable(intnum);
}
#else
static inline void xrp_interrupt_enable(uint32_t intnum)
{
	_xtos_interrupt_enable(intnum);
}
#endif

#ifdef HAVE_XTOS_INTERRUPT_DISABLE
static inline void xrp_interrupt_disable(uint32_t intnum)
{
	xtos_interrupt_disable(intnum);
}
#else
static inline void xrp_interrupt_disable(uint32_t intnum)
{
	_xtos_interrupt_disable(intnum);
}
#endif

#endif

#endif
