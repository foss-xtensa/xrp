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
			xrp_release_buffer(sbuf);
			xrp_release_buffer(dbuf);
			break;
		}

		pr_debug("%s: copy %d bytes from %p to %p\n",
		       __func__, sz, src, dst);
		memcpy(dst, src, sz);
		xrp_unmap_buffer(sbuf, src, NULL);
		xrp_unmap_buffer(dbuf, dst, NULL);
		xrp_release_buffer(sbuf);
		xrp_release_buffer(dbuf);
	}

	xrp_buffer_group_get_info(buffer_group, XRP_BUFFER_GROUP_SIZE_SIZE_T,
				  0, &bg_sz, sizeof(bg_sz), NULL);

	return bg_sz == i ? XRP_STATUS_SUCCESS : XRP_STATUS_FAILURE;
}

static enum xrp_status example_v2_handler(void *handler_context,
					  const void *in_data, size_t in_data_size,
					  void *out_data, size_t out_data_size,
					  struct xrp_buffer_group *buffer_group)
{
	const struct example_v2_cmd *cmd = in_data;
	struct example_v2_rsp *rsp = out_data;
	static volatile int c;

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
	case EXAMPLE_V2_CMD_LONG:
		c = 1;
#if HAVE_THREADS
		pr_debug("EXAMPLE_V2_CMD_LONG: enter\n");
		while (c == 1) {
		}
		pr_debug("EXAMPLE_V2_CMD_LONG: exit\n");
		c = 0;
#endif
		return XRP_STATUS_SUCCESS;
	case EXAMPLE_V2_CMD_SHORT:
		rsp->v = c;
#if HAVE_THREADS
		pr_debug("EXAMPLE_V2_CMD_SHORT\n");
		if (c)
			c = 2;
#endif
		return XRP_STATUS_SUCCESS;
	default:
		return XRP_STATUS_FAILURE;
	}
}

static enum xrp_status example_v3_handler(void *handler_context,
					  const void *in_data, size_t in_data_size,
					  void *out_data, size_t out_data_size,
					  struct xrp_buffer_group *buffer_group)
{
	const struct example_v3_cmd *cmd = in_data;
	struct example_v3_rsp *rsp = out_data;
	struct xrp_buffer *sbuf, *dbuf;
	void *src, *dst;
	volatile uint32_t i;

	(void)handler_context;

	if (in_data_size < sizeof(*cmd) ||
	    out_data_size < sizeof(*rsp))
		return XRP_STATUS_FAILURE;

	rsp->code = 0;

	sbuf = xrp_get_buffer_from_group(buffer_group, 0, NULL);
	dbuf = xrp_get_buffer_from_group(buffer_group, 1, NULL);

	if (!sbuf || !dbuf) {
		rsp->code = 1;
		goto out_release;
	}

	src = xrp_map_buffer(sbuf, cmd->off, cmd->sz, XRP_READ, NULL);
	dst = xrp_map_buffer(dbuf, cmd->off, cmd->sz, XRP_WRITE, NULL);

	if (!src || !dst) {
		rsp->code = 2;
		goto out_unmap;
	}

	pr_debug("%s: copy %d bytes from %p to %p\n",
		 __func__, cmd->sz, src, dst);
	memcpy(dst, src, cmd->sz);

	for (i = 0; i < cmd->timeout; ++i) {
	}

out_unmap:
	if (src)
		xrp_unmap_buffer(sbuf, src, NULL);
	if (dst)
		xrp_unmap_buffer(dbuf, dst, NULL);
out_release:
	if (sbuf)
		xrp_release_buffer(sbuf);
	if (dbuf)
		xrp_release_buffer(dbuf);

	return XRP_STATUS_SUCCESS;
}

static enum xrp_status test_ns(struct xrp_device *device)
{
	enum xrp_status status;
	char test_nsid[16][XRP_NAMESPACE_ID_SIZE];
	size_t i;

	for (i = 0; i < sizeof(test_nsid) / sizeof(test_nsid[0]); ++i) {
		size_t j;

		for (j = 0; j < XRP_NAMESPACE_ID_SIZE; ++j) {
			test_nsid[i][j] = rand();
		}
	}
	for (i = 0; i < sizeof(test_nsid) / sizeof(test_nsid[0]); ++i) {
		xrp_device_register_namespace(device, test_nsid[i],
					      NULL, NULL, &status);
		if (status != XRP_STATUS_SUCCESS) {
			pr_debug("xrp_register_namespace failed\n");
			return XRP_STATUS_FAILURE;
		}
	}
	for (i = 0; i < sizeof(test_nsid) / sizeof(test_nsid[0]); ++i) {
		xrp_device_unregister_namespace(device, test_nsid[i],
						&status);
		if (status != XRP_STATUS_SUCCESS) {
			pr_debug("xrp_unregister_namespace failed\n");
			return XRP_STATUS_FAILURE;
		}
	}
	return XRP_STATUS_SUCCESS;
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
	status = test_ns(device);
	if (status != XRP_STATUS_SUCCESS) {
		pr_debug("test_ns failed\n");
		goto err_release;
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
	xrp_device_register_namespace(device, XRP_EXAMPLE_V3_NSID,
				      example_v3_handler, NULL, &status);
	if (status != XRP_STATUS_SUCCESS) {
		pr_debug("xrp_register_namespace for XRP_EXAMPLE_V3_NSID failed\n");
		goto err_release;
	}
err_release:
	xrp_release_device(device);
	if (status != XRP_STATUS_SUCCESS)
		abort();
}
