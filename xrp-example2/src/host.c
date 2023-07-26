#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xrp_api.h"

/* Test default namespace */
static void func(int devid)
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

  int in_data = 0xdeadbeef;
  int out_data = 0;

	xrp_run_command_sync(queue, &in_data, sizeof(in_data), 
                       &out_data, sizeof(out_data),
            			     NULL, &status);
	assert(status == XRP_STATUS_SUCCESS);
	status = -1;

  int err = 0;
  if (out_data != in_data)
    err = 1;

  if (err)
   printf("Fail\n");
  else
    printf("Pass\n");

	xrp_release_queue(queue);
	xrp_release_device(device);
}

int main(int argc, char **argv)
{
	int devid = 0;
  func(devid);
  xrp_exit();
	return 0;
}
