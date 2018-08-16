/*
 * Copyright (c) 2016 - 2018 Cadence Design Systems Inc.
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
#include <stdlib.h>
#include <string.h>
#include "xrp_api.h"
#include "example_namespace.h"
#include "xrp_debug.h"

void xrp_run_command(const void *in_data, size_t in_data_size,
		     void *out_data, size_t out_data_size,
		     struct xrp_buffer_group *buffer_group,
		     enum xrp_status *status)
{
	(void)in_data;
	(void)in_data_size;
	(void)out_data;
	(void)out_data_size;
	(void)buffer_group;
	pr_debug("%s\n", __func__);
	if (status)
		*status = XRP_STATUS_SUCCESS;
}

static enum xrp_status example_v1_handler(void *handler_context,
					  const void *in_data, size_t in_data_size,
					  void *out_data, size_t out_data_size,
					  struct xrp_buffer_group *buffer_group)
{
	size_t i;
	uint32_t sz = 0;
	size_t bg_sz = 0;

	(void)handler_context;
	pr_debug("%s, in_data_size = %zu, out_data_size = %zu\n",
	       __func__, in_data_size, out_data_size);

	for (i = 0; i < in_data_size; ++i) {
		if (i < out_data_size)
			((uint8_t *)out_data)[i] =
				((uint8_t *)in_data)[i] + i;
	}

	if (in_data_size >= sizeof(sz))
		memcpy(&sz, in_data, sizeof(sz));

	for (i = 0; sz; i += 2) {
		struct xrp_buffer *sbuf = xrp_get_buffer_from_group(buffer_group, i, NULL);
		struct xrp_buffer *dbuf = xrp_get_buffer_from_group(buffer_group, i + 1, NULL);
		void *src, *dst;

		if (!sbuf || !dbuf)
			break;

		src = xrp_map_buffer(sbuf, 0, sz, XRP_READ, NULL);
		dst = xrp_map_buffer(dbuf, 0, sz, XRP_WRITE, NULL);

		if (!src || !dst) {
			xrp_release_buffer(sbuf, NULL);
			xrp_release_buffer(dbuf, NULL);
			break;
		}

		pr_debug("%s: copy %d bytes from %p to %p\n",
		       __func__, sz, src, dst);
		memcpy(dst, src, sz);
		xrp_unmap_buffer(sbuf, src, NULL);
		xrp_unmap_buffer(dbuf, dst, NULL);
		xrp_release_buffer(sbuf, NULL);
		xrp_release_buffer(dbuf, NULL);
	}

	xrp_buffer_group_get_info(buffer_group, XRP_BUFFER_GROUP_SIZE_SIZE_T,
				  0, &bg_sz, sizeof(bg_sz), NULL);

	return bg_sz == i ? XRP_STATUS_SUCCESS : XRP_STATUS_FAILURE;
}

static void example_v2_memcpy(uint32_t paddr, struct xrp_buffer *buf)
{
	size_t sz;
	void *p;
	if (!buf)
		return;
	xrp_buffer_get_info(buf, XRP_BUFFER_SIZE_SIZE_T, &sz, sizeof(sz), NULL);
	p = xrp_map_buffer(buf, 0, sz, XRP_WRITE, NULL);
	memcpy(p, (void *)paddr, sz);
	xrp_unmap_buffer(buf, p, NULL);
	xrp_release_buffer(buf, NULL);
}

static enum xrp_status example_v2_handler(void *handler_context,
					  const void *in_data, size_t in_data_size,
					  void *out_data, size_t out_data_size,
					  struct xrp_buffer_group *buffer_group)
{
	const struct example_v2_cmd *cmd = in_data;

	(void)handler_context;
	(void)out_data;
	(void)out_data_size;
	(void)buffer_group;

	if (in_data_size < sizeof(*cmd)) {
		return XRP_STATUS_FAILURE;
	}
	switch (cmd->cmd) {
	case EXAMPLE_V2_CMD_OK:
		return XRP_STATUS_SUCCESS;
	case EXAMPLE_V2_CMD_FAIL:
		return XRP_STATUS_FAILURE;
	case EXAMPLE_V2_CMD_MEMCPY:
		example_v2_memcpy(cmd->memcpy.paddr,
				  xrp_get_buffer_from_group(buffer_group, 0, NULL));
		return XRP_STATUS_SUCCESS;
	default:
		return XRP_STATUS_FAILURE;
	}
}

void __attribute__((constructor)) dsp_test_register(void)
{
	enum xrp_status status;
	struct xrp_device *device;

	device = xrp_open_device(0, &status);
	if (status != XRP_STATUS_SUCCESS) {
		pr_debug("xrp_open_device failed\n");
		abort();
	}
	xrp_device_register_namespace(device, XRP_EXAMPLE_V1_NSID,
				      example_v1_handler, NULL, &status);
	if (status != XRP_STATUS_SUCCESS) {
		pr_debug("xrp_register_namespace for XRP_EXAMPLE_V1_NSID failed\n");
		goto err_release;
	}
	xrp_device_register_namespace(device, XRP_EXAMPLE_V2_NSID,
				      example_v2_handler, NULL, &status);
	if (status != XRP_STATUS_SUCCESS) {
		pr_debug("xrp_register_namespace for XRP_EXAMPLE_V2_NSID failed\n");
		goto err_release;
	}
err_release:
	xrp_release_device(device, NULL);
	if (status != XRP_STATUS_SUCCESS)
		abort();
}
