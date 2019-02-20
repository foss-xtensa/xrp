/*
 * Copyright (c) 2017 - 2018 Cadence Design Systems Inc.
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
 * \file xrp_dsp_hw.h
 * \brief This section defines interface between generic and HW-specific DSP
 * libraries.
 */

#ifndef XRP_DSP_HW_H
#define XRP_DSP_HW_H

#define __weak __attribute__((weak))

/*!
 * \brief Initialize HW-specific DSP code
 *
 * DSP main must call this function before any other xrp_hw_* function is
 * called.
 */
void xrp_hw_init(void);

/*!
 * \brief Send IRQ to the host
 */
void xrp_hw_send_host_irq(void);

/*!
 * \brief Wait for the IRQ from the host
 *
 * The XRP is idle. If there's no other work go to low-power state and wait
 * for IRQ from the host.
 */
void xrp_hw_wait_device_irq(void);

/*!
 * \brief Set HW-specific data passed from the host
 *
 * Consume HW-specific data passed from the host during synchronization.
 * Format of this data is specific to the HW port and both DSP and kernel
 * driver must agree about it.
 */
void xrp_hw_set_sync_data(void *p) __weak;

/*!
 * \brief Indicate panic to the host
 *
 * Indicate to the host that the DSP cannot recover from the state it is in.
 * This function makes a best effort to inform the host, but there are no
 * guarantees. It may as well do nothing. In the worst case, the host will
 * observe a timeout on its request and then perform recovery.
 */
void xrp_hw_panic(void);

#endif
