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

#ifndef XRP_DSP_SYNC_H
#define XRP_DSP_SYNC_H

#include <xtensa/config/core.h>
#if XCHAL_HAVE_RELEASE_SYNC
#include <xtensa/tie/xt_sync.h>
#else
#include <xtensa/tie/xt_core.h>
#endif

#if XCHAL_HAVE_RELEASE_SYNC
static inline uint32_t xrp_l32ai(volatile void *p)
{
	return XT_L32AI((const volatile unsigned *)p, 0);
}

static inline void xrp_s32ri(uint32_t v, volatile void *p)
{
	XT_S32RI(v, (volatile unsigned *)p, 0);
}
#else
static inline uint32_t xrp_l32ai(volatile void *p)
{
	uint32_t v = *(const volatile uint32_t *)p;
	XT_MEMW();
	return v;
}

static inline void xrp_s32ri(uint32_t v, volatile void *p)
{
	XT_MEMW();
	*(volatile uint32_t *)p = v;
}
#endif

#endif
