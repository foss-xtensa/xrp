/*
 * Copyright (c) 2019 Cadence Design Systems Inc.
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

/*!
 * \file xrp_dsp_user.h
 * \brief This section defines reverse interface between the generic DSP
 * library and its user.
 */

#ifndef XRP_DSP_USER_H
#define XRP_DSP_USER_H

#include <stdint.h>
#include "xrp_api.h"

#define __weak __attribute__((weak))

/*!
 * \brief Create hardware queues
 *
 * Create handlers for n hardware queues with specified priorities.
 * This function is optional, when it's not implemented the firmware does not
 * support multiqueue feature.
 *
 * \param n: number of queues
 * \param[in,out] priority: requested/assigned queue priorities
 * \return XRP_STATUS_SUCCESS if all queues were created,
 *         XRP_STATUS_FAILURE otherwise.
 */
enum xrp_status xrp_user_create_queues(unsigned n,
				       uint32_t priority[]) __weak;

#endif
