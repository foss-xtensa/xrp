/*
 * Copyright (c) 2026 Cadence Design Systems Inc.
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

#ifndef _XRP_THREAD_FREERTOS_IMPL_H
#define _XRP_THREAD_FREERTOS_IMPL_H

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "event_groups.h"

#if ( configSUPPORT_STATIC_ALLOCATION != 1 )
#error FreeRTOS XRP threading layer requires static allocation
#endif

/* Assert if any XRP structure allocations fail.
 * NOTE: Large number of threads are required for the
 * standalone-hosted example. The following static allocations
 * should be minimized if memory usage is a concern.
 */
#define XRP_ALLOC_ASSERT    1
#if (XRP_ALLOC_ASSERT)
#define XRP_ASSERT(x)       configASSERT(x)
#else
#define XRP_ASSERT(x)
#endif


/* Statically allocated mutex buffers.
 * Allocation time is not optimized and is O(n).
 */
#define XRP_MUTEX_MAX       64
#define XRP_MUTEX_RSVD0     0   /* For mutex allocation */
#define XRP_MUTEX_AVAIL     1

typedef struct xrp_mutex_mem {
    StaticSemaphore_t buf;
    SemaphoreHandle_t handle;
    int in_use;
} xrp_mutex_mem;


/* Statically allocated cond/event-group buffers.
 * Allocation time is not optimized and is O(n).
 */
#define XRP_EVENT_MAX       64

typedef struct xrp_event_mem {
    StaticEventGroup_t buf;
    EventGroupHandle_t c_handle;
    xrp_mutex_mem *    m_handle;
    int in_use;
} xrp_event_mem;


/* Statically allocated task buffers and stacks.
 * Allocation time is not optimized and is O(n).
 */
#define XRP_TASK_MAX        32
#define XRP_TASK_STACK_SIZE 4096  /* units are in StackType_t */

typedef struct xrp_task_mem {
    StaticTask_t buf;
    StackType_t  stack[XRP_TASK_STACK_SIZE];
    TaskHandle_t handle;
    void *(*thread_func)(void *);
    void *thread_parm;
    StaticSemaphore_t done_buf;
    SemaphoreHandle_t done_handle;
    int in_use;
} xrp_task_mem;


/* Main XRP abstraction layer type defines for FreeRTOS */
typedef xrp_task_mem  *xrp_thread;
typedef xrp_mutex_mem *xrp_mutex;
typedef xrp_event_mem *xrp_cond;

static inline void xrp_mutex_init(xrp_mutex *p)
{
    static xrp_mutex_mem xrp_mutex_buffers[XRP_MUTEX_MAX];
    static SemaphoreHandle_t xrp_mutex_alloc_mtx = NULL;
    if (!xrp_mutex_alloc_mtx) {
        xrp_mutex_alloc_mtx = xSemaphoreCreateMutexStatic(&(xrp_mutex_buffers[XRP_MUTEX_RSVD0].buf));
        xrp_mutex_buffers[XRP_MUTEX_RSVD0].handle = NULL; /* Do not use in XRP */
        xrp_mutex_buffers[XRP_MUTEX_RSVD0].in_use = 1;
    }
    XRP_ASSERT(p);
    *p = NULL;
    xSemaphoreTake(xrp_mutex_alloc_mtx, portMAX_DELAY);
    for (int i = XRP_MUTEX_AVAIL; i < XRP_MUTEX_MAX; i++) {
        xrp_mutex_mem *m = &(xrp_mutex_buffers[i]);
        if (m->in_use == 0) {
            m->in_use = 1;
            m->handle = xSemaphoreCreateMutexStatic(&(m->buf));
            *p = m;
            break;
        }
    }
    XRP_ASSERT(*p != NULL);
    xSemaphoreGive(xrp_mutex_alloc_mtx);
}

static inline void xrp_mutex_lock(xrp_mutex *p)
{
    XRP_ASSERT(p);
    xrp_mutex_mem *m = *p;
    /* May block */
    xSemaphoreTake(m->handle, portMAX_DELAY);
}

static inline void xrp_mutex_unlock(xrp_mutex *p)
{
    XRP_ASSERT(p);
    xrp_mutex_mem *m = *p;
    xSemaphoreGive(m->handle);
}

static inline void xrp_mutex_destroy(xrp_mutex *p)
{
    XRP_ASSERT(p);
    xrp_mutex_mem *m = *p;
    if (m->in_use) {
        *p = NULL;
        m->handle = NULL;
        m->in_use = 0;
    }
}

static inline void xrp_cond_init(xrp_cond *p)
{
    static xrp_event_mem xrp_event_buffers[XRP_EVENT_MAX];
    static xrp_mutex_mem xrp_event_mutex_buffer;
    static SemaphoreHandle_t xrp_event_alloc_mtx = NULL;
    if (!xrp_event_alloc_mtx) {
        xrp_event_alloc_mtx = xSemaphoreCreateMutexStatic(&(xrp_event_mutex_buffer.buf));
        xrp_event_mutex_buffer.handle = NULL; /* Do not use in XRP */
        xrp_event_mutex_buffer.in_use = 1;
    }

    XRP_ASSERT(p);
    *p = NULL;
    xSemaphoreTake(xrp_event_alloc_mtx, portMAX_DELAY);
    for (int i = 0; i < XRP_EVENT_MAX; i++) {
        xrp_event_mem *e = &(xrp_event_buffers[i]);
        if (e->in_use == 0) {
            e->in_use = 1;
            e->c_handle = xEventGroupCreateStatic(&(e->buf));
            xrp_mutex_init(&(e->m_handle));
            *p = e;
            break;
        }
    }
    XRP_ASSERT(*p != NULL);
    xSemaphoreGive(xrp_event_alloc_mtx);
}

static inline void xrp_cond_lock(xrp_cond *p)
{
    XRP_ASSERT(p);
    xrp_event_mem *e = *p;
    xrp_mutex_lock(&(e->m_handle));
}

static inline void xrp_cond_unlock(xrp_cond *p)
{
    XRP_ASSERT(p);
    xrp_event_mem *e = *p;
    xrp_mutex_unlock(&(e->m_handle));
}

static inline void xrp_cond_broadcast(xrp_cond *p)
{
    XRP_ASSERT(p);
    xrp_event_mem *e = *p;
    xEventGroupSetBits(e->c_handle, 0xFFFF);
}

static inline void xrp_cond_wait(xrp_cond *p)
{
    XRP_ASSERT(p);
    xrp_event_mem *e = *p;
    xrp_mutex_unlock(&(e->m_handle));
    xEventGroupWaitBits(e->c_handle, 0xFFFF, pdTRUE, pdTRUE, portMAX_DELAY);
    xrp_mutex_lock(&(e->m_handle));
}

static inline void xrp_cond_destroy(xrp_cond *p)
{
    XRP_ASSERT(p);
    xrp_event_mem *e = *p;
    if (e->in_use) {
        *p = NULL;
        xrp_mutex_destroy(&(e->m_handle));
        e->m_handle = NULL;
        e->c_handle = NULL;
        e->in_use = 0;
    }
}

static inline void xrp_thread_wrapper(void *arg)
{
    xrp_task_mem *t = (xrp_task_mem *)arg;
    t->thread_func(t->thread_parm);
    xSemaphoreGive(t->done_handle);
    vTaskSuspend(NULL);
}

static inline int xrp_thread_create(xrp_thread *thread, int priority,
                    void *(*thread_func)(void *),
                    void *p)
{
    static xrp_task_mem xrp_task_buffers[XRP_TASK_MAX];
    static xrp_mutex_mem xrp_task_mutex_buffer;
    static SemaphoreHandle_t xrp_task_alloc_mtx = NULL;
    int rv = -1;
    if (!xrp_task_alloc_mtx) {
        xrp_task_alloc_mtx = xSemaphoreCreateMutexStatic(&(xrp_task_mutex_buffer.buf));
        xrp_task_mutex_buffer.handle = NULL; /* Do not use in XRP */
        xrp_task_mutex_buffer.in_use = 1;
    }
    XRP_ASSERT(thread);
    *thread = NULL;
    xSemaphoreTake(xrp_task_alloc_mtx, portMAX_DELAY);
    for (int i = 0; i < XRP_TASK_MAX; i++) {
        xrp_task_mem *t = &(xrp_task_buffers[i]);
        if (t->in_use == 0) {
            t->in_use = 1;
            t->thread_func = thread_func;
            t->thread_parm = p;
            t->done_handle = xSemaphoreCreateCountingStatic(1, 0, &(t->done_buf));
            t->handle = xTaskCreateStatic(xrp_thread_wrapper,
                                          "xrp_task",
                                          XRP_TASK_STACK_SIZE,
                                          t,
                                          priority,
                                          t->stack,
                                          &(t->buf));
            *thread = t;
            rv = (t->handle == NULL) ? -2 : 0;
            break;
        }
    }
    XRP_ASSERT(*thread != NULL);
    xSemaphoreGive(xrp_task_alloc_mtx);
    return rv;
}

static inline int xrp_thread_join(xrp_thread *thread)
{
    XRP_ASSERT(thread);
    xrp_task_mem *t = *thread;
    if (!(t->in_use)) {
        return -1;
    }
    xSemaphoreTake(t->done_handle, portMAX_DELAY);
    return -1;
}

static inline int xrp_thread_detach(xrp_thread *thread)
{
    int rv = -1;
    XRP_ASSERT(thread);
    xrp_task_mem *t = *thread;
    if (t->in_use) {
        *thread = NULL;
        vTaskDelete(t->handle);
        vSemaphoreDelete(t->done_handle);
        t->handle = NULL;
        t->done_handle = NULL;
        t->thread_func = NULL;
        t->thread_parm = NULL;
        t->in_use = 0;
        rv = 0;
    }
    return rv;
}

#endif  // _XRP_THREAD_FREERTOS_IMPL_H
