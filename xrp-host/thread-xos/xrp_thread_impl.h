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

#ifndef _XRP_THREAD_XOS_IMPL_H
#define _XRP_THREAD_XOS_IMPL_H

#include <stdlib.h>
#include <xtensa/xos.h>

typedef struct xrp_thread {
	XosThread thread;
	void *stack;
	void *(*func)(void *);
} xrp_thread;

typedef XosMutex xrp_mutex;

typedef struct xrp_cond {
	xrp_mutex mutex;
	XosCond cond;
} xrp_cond;

static inline void xrp_mutex_init(xrp_mutex *p)
{
	xos_mutex_create(p, 0, 0);
}

static inline void xrp_mutex_lock(xrp_mutex *p)
{
	xos_mutex_lock(p);
}

static inline void xrp_mutex_unlock(xrp_mutex *p)
{
	xos_mutex_unlock(p);
}

static inline void xrp_mutex_destroy(xrp_mutex *p)
{
	xos_mutex_delete(p);
}

static inline void xrp_cond_init(xrp_cond *p)
{
	xrp_mutex_init(&p->mutex);
	xos_cond_create(&p->cond);
}

static inline void xrp_cond_lock(xrp_cond *p)
{
	xrp_mutex_lock(&p->mutex);
}

static inline void xrp_cond_unlock(xrp_cond *p)
{
	xrp_mutex_unlock(&p->mutex);
}

static inline void xrp_cond_broadcast(xrp_cond *p)
{
	xos_cond_signal(&p->cond, 0);
}

static inline void xrp_cond_wait(xrp_cond *p)
{
	uint32_t prev = xos_disable_interrupts();

	xrp_mutex_unlock(&p->mutex);
	xos_cond_wait(&p->cond, NULL, 0);
	xrp_mutex_lock(&p->mutex);
	xos_restore_interrupts(prev);
}

static inline void xrp_cond_destroy(xrp_cond *p)
{
	xrp_mutex_destroy(&p->mutex);
	xos_cond_delete(&p->cond);
}

static inline int32_t xrp_xos_thread_func(void *arg, int32_t wake_value)
{
	xrp_thread *thread = (xrp_thread *)xos_thread_id();
	(void)wake_value;

	thread->func(arg);
	return 0;
}

extern char xrp_xos_thread_stack_size[] __attribute__((weak));

static inline int xrp_thread_create(xrp_thread *thread, int priority,
				    void *(*thread_func)(void *),
				    void *p)
{
	uint32_t thread_stack_size = (uint32_t)xrp_xos_thread_stack_size;
	void *stack;
	int32_t rc;

	if (!thread_stack_size)
		thread_stack_size = 0x2000 + XOS_STACK_EXTRA;

	if (priority)
		priority += xos_thread_get_priority(XOS_THREAD_SELF);

	stack = malloc(thread_stack_size);
	if (stack == NULL)
		return 0;
	thread->stack = stack;
	thread->func = thread_func;
	rc = xos_thread_create(&thread->thread, NULL,
			       xrp_xos_thread_func, p,
			       "xrp_xos_thread_func",
			       stack, thread_stack_size,
			       priority, NULL, 0);
	return rc == XOS_OK;
}

static inline int xrp_thread_join(xrp_thread *thread)
{
	int rc = xos_thread_join(&thread->thread, NULL) == XOS_OK;

	xos_thread_delete(&thread->thread);
	free(thread->stack);
	return rc;
}

static inline int xrp_thread_detach(xrp_thread *thread)
{
	(void)thread;
	return 1;
}

#endif
