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

#ifndef _XRP_THREAD_SINGLE_IMPL_H
#define _XRP_THREAD_SINGLE_IMPL_H

typedef struct xrp_mutex {
} xrp_mutex;

typedef struct xrp_cond {
} xrp_cond;

static inline void xrp_mutex_init(xrp_mutex *p)
{
	(void)p;
}

static inline void xrp_mutex_lock(xrp_mutex *p)
{
	(void)p;
}

static inline void xrp_mutex_unlock(xrp_mutex *p)
{
	(void)p;
}

static inline void xrp_mutex_destroy(xrp_mutex *p)
{
	(void)p;
}

static inline void xrp_cond_init(xrp_cond *p)
{
	(void)p;
}

static inline void xrp_cond_lock(xrp_cond *p)
{
	(void)p;
}

static inline void xrp_cond_unlock(xrp_cond *p)
{
	(void)p;
}

static inline void xrp_cond_broadcast(xrp_cond *p)
{
	(void)p;
}

static inline void xrp_cond_wait(xrp_cond *p)
{
	(void)p;
}

static inline void xrp_cond_destroy(xrp_cond *p)
{
	(void)p;
}

#endif
