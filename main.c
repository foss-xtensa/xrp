#include <stdio.h>
#include <string.h>
#include "xrp_api.h"

int main()
{
	enum xrp_status status;
	struct xrp_buffer *buf = xrp_create_buffer(1024, NULL, &status);
	void *data = xrp_map_buffer(buf, 0, 1024, XRP_MAP_READ_WRITE, &status);
	struct xrp_context *context = xrp_create_context(&status);
	int idx;

	memset(data, 'z', 1024);

	xrp_unmap_buffer(buf, data, &status);

	idx = xrp_add_buffer_to_context(context, buf, &status);
	printf("add_buffer_to_context: %d\n", idx);

	xrp_run_command_sync(NULL, 0, context);
	xrp_release_context(context, &status);
	xrp_release_buffer(buf, &status);

	return 0;
}
