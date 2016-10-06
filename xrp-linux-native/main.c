#include <stdio.h>
#include <string.h>
#include "xrp_api.h"

int main()
{
	enum xrp_status status;
	struct xrp_device *device = xrp_open_device(0, &status);
	struct xrp_queue *queue = xrp_create_queue(device, &status);
	struct xrp_buffer_group *group = xrp_create_buffer_group(&status);
	struct xrp_buffer *buf = xrp_create_buffer(device, 1024, NULL, &status);
	void *data = xrp_map_buffer(buf, 0, 1024, XRP_READ_WRITE, &status);
	struct xrp_event *event;
	int idx;

	memset(data, 'z', 1024);

	xrp_unmap_buffer(buf, data, &status);

	idx = xrp_add_buffer_to_group(group, buf, XRP_READ_WRITE, &status);
	printf("add_buffer_to_group: %d\n", idx);

	xrp_enqueue_command(queue, NULL, 0, NULL, 0, group, &event, &status);
	xrp_release_buffer_group(group, &status);
	xrp_release_buffer(buf, &status);
	xrp_release_queue(queue, &status);
	xrp_wait(event, &status);
	xrp_release_event(event, &status);

	return 0;
}
