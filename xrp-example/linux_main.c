#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "xrp_api.h"

static void f1(int devid)
{
	enum xrp_status status;
	struct xrp_device *device = xrp_open_device(devid, &status);
	struct xrp_queue *queue = xrp_create_queue(device, &status);
	char in_buf[32];
	char out_buf[32];
	int i, j;

	for (i = 0; i <= 32; ++i) {
		memset(in_buf, i, sizeof(in_buf));
		memset(out_buf, 0, sizeof(out_buf));
		xrp_run_command_sync(queue,
				     in_buf, i,
				     out_buf, i,
				     NULL, &status);

		for (j = 0; j < 32; ++j) {
			assert(out_buf[j] == (j < i ? i + j : 0));
		}
	}

	xrp_release_queue(queue, &status);
	xrp_release_device(device, &status);
}

static void f2(int devid)
{
	enum xrp_status status;
	struct xrp_device *device = xrp_open_device(devid, &status);
	struct xrp_queue *queue = xrp_create_queue(device, &status);
	struct xrp_buffer_group *group = xrp_create_buffer_group(&status);
	struct xrp_buffer *buf = xrp_create_buffer(device, 1024, NULL, &status);
	void *data = xrp_map_buffer(buf, 0, 1024, XRP_READ_WRITE, &status);
	struct xrp_event *event;

	memset(data, 'z', 1024);

	xrp_unmap_buffer(buf, data, &status);

	xrp_add_buffer_to_group(group, buf, XRP_READ_WRITE, &status);

	xrp_enqueue_command(queue, NULL, 0, NULL, 0, group, &event, &status);
	xrp_release_buffer_group(group, &status);
	xrp_release_buffer(buf, &status);
	xrp_release_queue(queue, &status);
	xrp_wait(event, &status);
	xrp_release_event(event, &status);
	xrp_release_device(device, &status);
}

static void f3(int devid)
{
	enum xrp_status status;
	struct xrp_device *device = xrp_open_device(devid, &status);
	struct xrp_queue *queue = xrp_create_queue(device, &status);
	uint32_t sz;
	int i;

	for (sz = 2048; sz < 16384; sz <<= 1) {
		fprintf(stderr, "%s: sz = %zd\n", __func__, (size_t)sz);
		for (i = 0; i < 4; ++i) {
			void *p1 = (i & 1) ? malloc(sz) : NULL;
			void *p2 = (i & 2) ? malloc(sz) : NULL;
			struct xrp_buffer_group *group = xrp_create_buffer_group(&status);
			struct xrp_buffer *buf1 = xrp_create_buffer(device, sz, p1, &status);
			struct xrp_buffer *buf2 = xrp_create_buffer(device, sz, p2, &status);
			void *data1 = xrp_map_buffer(buf1, 0, sz, XRP_READ_WRITE, &status);
			void *data2;

			memset(data1, i + 3 + sz / 512, sz);
			xrp_unmap_buffer(buf1, data1, &status);

			xrp_add_buffer_to_group(group, buf1, XRP_READ, &status);
			xrp_add_buffer_to_group(group, buf2, XRP_WRITE, &status);

			xrp_run_command_sync(queue, &sz, sizeof(sz), NULL, 0, group, &status);
			xrp_release_buffer_group(group, &status);

			data1 = xrp_map_buffer(buf1, 0, sz, XRP_READ_WRITE, &status);
			data2 = xrp_map_buffer(buf2, 0, sz, XRP_READ_WRITE, &status);
			assert(data1);
			assert(data2);
			fprintf(stderr, "comparing %p vs %p\n", data1, data2);
			assert(memcmp(data1, data2, sz) == 0);
			xrp_unmap_buffer(buf1, data1, &status);
			xrp_unmap_buffer(buf2, data2, &status);
			xrp_release_buffer(buf1, &status);
			xrp_release_buffer(buf2, &status);
			free(p1);
			free(p2);
		}
	}
	xrp_release_queue(queue, &status);
	xrp_release_device(device, &status);
}

int main(int argc, char **argv)
{
	int devid = 0;

	if (argc > 1)
		sscanf(argv[1], "%i", &devid);
	f1(devid);
	printf("=======================================================\n");
	f2(devid);
	printf("=======================================================\n");
	f3(devid);
	return 0;
}