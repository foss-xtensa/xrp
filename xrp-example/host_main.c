/*
 * Copyright (c) 2016 - 2017 Cadence Design Systems Inc.
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

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xrp_api.h"
#include "example_namespace.h"
#ifdef HAVE_THREADS_XOS
#include <xtensa/xos.h>
#endif

/* Test data transfer from and to in/out buffers */
static void f1(int devid)
{
	enum xrp_status status = -1;
	struct xrp_device *device;
	struct xrp_queue *queue;
	char in_buf[32];
	char out_buf[32];
	int i, j;

	device = xrp_open_device(devid, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	queue = xrp_create_ns_queue(device, XRP_EXAMPLE_V1_NSID, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	for (i = 0; i <= 32; ++i) {
		int mismatch = 0;
		memset(in_buf, i, sizeof(in_buf));
		memset(out_buf, 0, sizeof(out_buf));
		xrp_run_command_sync(queue,
				     in_buf, i,
				     out_buf, i,
				     NULL, &status);
		assert(status == XRP_STATUS_SUCCESS);
		status = -1;

		for (j = 0; j < 32; ++j)
			mismatch += (out_buf[j] != (j < i ? i + j : 0));

		if (!mismatch)
			continue;

		for (j = 0; j < 32; ++j) {
			int ne = (out_buf[j] != (j < i ? i + j : 0));
			fprintf(stderr,
				"out_buf[%d] (%p) == 0x%02x %c= expected: 0x%02x\n",
				j, out_buf + j, (uint8_t)out_buf[j],
				ne ? '!' : '=',
				(j < i ? i + j : 0));
		}
		assert(mismatch == 0);
	}

	xrp_release_queue(queue, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_device(device, &status);
	assert(status == XRP_STATUS_SUCCESS);
}

/* Test asynchronous API */
static void f2(int devid)
{
	enum xrp_status status = -1;
	struct xrp_device *device;
	struct xrp_queue *queue;
	struct xrp_buffer_group *group;
	struct xrp_buffer *buf;
	void *data;
	struct xrp_event *event[2];

	device = xrp_open_device(devid, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	queue = xrp_create_ns_queue(device, XRP_EXAMPLE_V1_NSID, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	group = xrp_create_buffer_group(&status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	buf = xrp_create_buffer(device, 1024, NULL, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	data = xrp_map_buffer(buf, 0, 1024, XRP_READ_WRITE, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	memset(data, 'z', 1024);

	xrp_unmap_buffer(buf, data, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	xrp_add_buffer_to_group(group, buf, XRP_READ_WRITE, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	xrp_enqueue_command(queue, NULL, 0, NULL, 0, group, NULL, &status);
	assert(status == XRP_STATUS_SUCCESS);
	xrp_enqueue_command(queue, NULL, 0, NULL, 0, group, event + 0, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_enqueue_command(queue, NULL, 0, NULL, 0, group, event + 1, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_buffer_group(group, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_buffer(buf, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_queue(queue, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_wait(event[1], &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_event_status(event[0], &status);
	assert(status != XRP_STATUS_PENDING);
	status = -1;
	xrp_wait(event[0], &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_event(event[0], &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_event(event[1], &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_device(device, &status);
	assert(status == XRP_STATUS_SUCCESS);
}

/* Test data transfer from and to device and user buffers */
static void f3(int devid)
{
	enum xrp_status status = -1;
	struct xrp_device *device;
	struct xrp_queue *queue;
	uint32_t sz;
	unsigned i;


	device = xrp_open_device(devid, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	queue = xrp_create_ns_queue(device, XRP_EXAMPLE_V1_NSID, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	for (sz = 2048; sz < 16384; sz <<= 1) {
		fprintf(stderr, "%s: sz = %zd\n", __func__, (size_t)sz);
		for (i = 0; i < 4; ++i) {
			void *p1 = (i & 1) ? malloc(sz) : NULL;
			void *p2 = (i & 2) ? malloc(sz) : NULL;
			struct xrp_buffer_group *group;
			struct xrp_buffer *buf1;
			struct xrp_buffer *buf2;
			void *data1;
			void *data2;

			group = xrp_create_buffer_group(&status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;
			buf1 = xrp_create_buffer(device, sz, p1, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;
			buf2 = xrp_create_buffer(device, sz, p2, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;

			data1 = xrp_map_buffer(buf1, 0, sz, XRP_READ_WRITE, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;

			memset(data1, i + 3 + sz / 512, sz);
			xrp_unmap_buffer(buf1, data1, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;

			xrp_add_buffer_to_group(group, buf1, XRP_READ, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;
			xrp_add_buffer_to_group(group, buf2, XRP_WRITE, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;

			xrp_run_command_sync(queue, &sz, sizeof(sz), NULL, 0, group, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;
			xrp_release_buffer_group(group, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;

			data1 = xrp_map_buffer(buf1, 0, sz, XRP_READ_WRITE, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;
			data2 = xrp_map_buffer(buf2, 0, sz, XRP_READ_WRITE, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;
			assert(data1);
			assert(data2);
			fprintf(stderr, "comparing %p vs %p\n", data1, data2);
			if (memcmp(data1, data2, sz)) {
				for (i = 0; i < sz; ++i) {
					uint8_t v1 = ((uint8_t *)data1)[i];
					uint8_t v2 = ((uint8_t *)data2)[i];
					if (v1 != v2) {
						fprintf(stderr,
							"data1[%d] (%p) (== 0x%02x) != data2[%d] (%p) (== 0x%02x)\n",
							i, data1 + i, v1, i, data2 + i, v2);

					}
				}
				assert(0);
			}
			xrp_unmap_buffer(buf1, data1, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;
			xrp_unmap_buffer(buf2, data2, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;
			xrp_release_buffer(buf1, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;
			xrp_release_buffer(buf2, &status);
			assert(status == XRP_STATUS_SUCCESS);
			status = -1;
			free(p1);
			free(p2);
		}
	}
	xrp_release_queue(queue, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_device(device, &status);
	assert(status == XRP_STATUS_SUCCESS);
}

/* Test xrp_set_buffer_in_group */
static void f4(int devid)
{
	enum xrp_status status = -1;
	struct xrp_device *device;
	struct xrp_queue *queue;
	struct xrp_buffer_group *group;
	struct xrp_buffer *buf1;
	struct xrp_buffer *buf2;
	struct xrp_buffer *buf3;
	size_t i;

	device = xrp_open_device(devid, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	queue = xrp_create_ns_queue(device, XRP_EXAMPLE_V1_NSID, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	group = xrp_create_buffer_group(&status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	buf1 = xrp_create_buffer(device, 1, NULL, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	buf2 = xrp_create_buffer(device, 1, NULL, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	i = xrp_add_buffer_to_group(group, buf1, XRP_READ, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_set_buffer_in_group(group, i, buf2, XRP_READ, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_set_buffer_in_group(group, i + 1, buf2, XRP_READ, &status);
	assert(status == XRP_STATUS_FAILURE);
	status = -1;
	buf3 = xrp_get_buffer_from_group(group, i, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	assert(buf3 == buf2);
	xrp_release_buffer(buf1, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_buffer(buf2, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_buffer(buf3, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_buffer_group(group, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_queue(queue, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_device(device, &status);
	assert(status == XRP_STATUS_SUCCESS);
}

/* Test xrp_buffer[_group]_get_info */
static void f5(int devid)
{
	enum xrp_status status = -1;
	struct xrp_device *device;
	struct xrp_queue *queue;
	struct xrp_buffer_group *group;
	struct xrp_buffer *buf1;
	struct xrp_buffer *buf2;
	size_t i;
	size_t sz;
	void *ptr;
	enum xrp_access_flags flags;

	device = xrp_open_device(devid, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	queue = xrp_create_ns_queue(device, XRP_EXAMPLE_V1_NSID, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	group = xrp_create_buffer_group(&status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	buf1 = xrp_create_buffer(device, 1, NULL, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	buf2 = xrp_create_buffer(device, sizeof(i), &i, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	i = xrp_add_buffer_to_group(group, buf1, XRP_READ, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	xrp_buffer_get_info(buf1, XRP_BUFFER_SIZE_SIZE_T,
			    &sz, sizeof(sz), &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	assert(sz == 1);
	xrp_buffer_get_info(buf1, XRP_BUFFER_HOST_POINTER_PTR,
			    &ptr, sizeof(ptr), &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	assert(ptr == NULL);
	xrp_buffer_get_info(buf2, XRP_BUFFER_HOST_POINTER_PTR,
			    &ptr, sizeof(ptr), &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	assert(ptr == &i);

	xrp_buffer_group_get_info(group, XRP_BUFFER_GROUP_BUFFER_FLAGS_ENUM, i,
				  &flags, sizeof(flags), &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	assert(flags == XRP_READ);
	xrp_buffer_group_get_info(group, XRP_BUFFER_GROUP_SIZE_SIZE_T, 0,
				  &sz, sizeof(sz), &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	assert(sz == 1);

	xrp_release_buffer(buf1, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_buffer(buf2, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_buffer_group(group, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_queue(queue, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_device(device, &status);
	assert(status == XRP_STATUS_SUCCESS);
}

/* Test default namespace */
static void f6(int devid)
{
	enum xrp_status status = -1;
	struct xrp_device *device;
	struct xrp_queue *queue;

	device = xrp_open_device(devid, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	queue = xrp_create_queue(device, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	xrp_run_command_sync(queue,
			     NULL, 0,
			     NULL, 0,
			     NULL, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	xrp_release_queue(queue, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_device(device, &status);
	assert(status == XRP_STATUS_SUCCESS);
}

/* Test command errors */
static void f7(int devid)
{
	enum xrp_status status = -1;
	struct xrp_device *device;
	struct xrp_queue *queue;
	struct example_v2_cmd cmd = {
		.cmd = EXAMPLE_V2_CMD_OK,
	};

	device = xrp_open_device(devid, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	queue = xrp_create_ns_queue(device, XRP_EXAMPLE_V2_NSID, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	xrp_run_command_sync(queue,
			     &cmd, sizeof(cmd),
			     NULL, 0,
			     NULL, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

	cmd.cmd = EXAMPLE_V2_CMD_FAIL;

	xrp_run_command_sync(queue,
			     &cmd, sizeof(cmd),
			     NULL, 0,
			     NULL, &status);
	assert(status == XRP_STATUS_FAILURE);
	status = -1;

	xrp_release_queue(queue, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;
	xrp_release_device(device, &status);
	assert(status == XRP_STATUS_SUCCESS);
}

enum {
	CMD_TEST,

	CMD_N,
};

int main(int argc, char **argv)
{
	int devid = 0;
	static const char * const cmd[CMD_N] = {
		[CMD_TEST] = "test",
	};
	int i = 0;

#ifdef HAVE_THREADS_XOS
	xos_set_clock_freq(XOS_CLOCK_FREQ);
	xos_start_main("main", 0, 0);
#endif
	if (argc > 1)
		sscanf(argv[1], "%i", &devid);
	if (argc > 2) {
		for (i = 0; i < CMD_N; ++i)
			if (strcmp(argv[2], cmd[i]) == 0)
				break;
		if (i == CMD_N) {
			fprintf(stderr, "%s: unrecognized command: %s\n", argv[0], argv[2]);
			return 1;
		}
	}
	switch(i) {
	case CMD_TEST:
		{
			unsigned long tests = -1;

			if (argc > 3)
				sscanf(argv[3], "%li", &tests);

			if (tests & 1) {
				f1(devid);
				printf("=======================================================\n");
			}
			if (tests & 2) {
				f2(devid);
				printf("=======================================================\n");
			}
			if (tests & 4) {
				f3(devid);
				printf("=======================================================\n");
			}
			if (tests & 8) {
				f4(devid);
				printf("=======================================================\n");
			}
			if (tests & 0x10) {
				f5(devid);
				printf("=======================================================\n");
			}
			if (tests & 0x20) {
				f6(devid);
				printf("=======================================================\n");
			}
			if (tests & 0x40) {
				f7(devid);
			}
		}
		break;
	}
	return 0;
}
