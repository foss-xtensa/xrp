/*
 * xrp_property: HW-specific configuration abstraction interface
 *
 * Copyright (c) 2020 Cadence Design Systems, Inc.
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
 *
 * Alternatively you can use and distribute this file under the terms of
 * the GNU General Public License version 2 or later.
 */

#ifndef XRP_PROPERTY_H
#define XRP_PROPERTY_H

#include "xrp_internal.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/property.h>
#else
#define device_property_read_string(dev, name, val) (-ENXIO)
#define device_property_read_u32_array(dev, name, val, nval) (-ENXIO)
#endif

static inline long xrp_property_read_string(struct xvp *xvp,
					    const char *name,
					    const char **val)
{
	if (xvp->hw_ops->property_read_string) {
		return xvp->hw_ops->property_read_string(xvp->hw_arg,
							 name, val);
	} else {
		return device_property_read_string(xvp->dev,
						   name, val);
	}
}

static inline long xrp_property_read_u32_array(struct xvp *xvp,
					       const char *name,
					       u32 *val, size_t nval)
{
	if (xvp->hw_ops->property_read_u32_array) {
		return xvp->hw_ops->property_read_u32_array(xvp->hw_arg,
							    name, val, nval);
	} else {
		return device_property_read_u32_array(xvp->dev,
						      name, val, nval);
	}
}

#endif
