#ifndef _XRP_API_H
#define _XRP_API_H

#include <stddef.h>

/*
 * User API.
 */

struct xrp_device;
struct xrp_queue;
struct xrp_buffer;
struct xrp_buffer_group;
struct xrp_event;

enum xrp_status {
	XRP_STATUS_SUCCESS,
	XRP_STATUS_FAILURE,
};
enum xrp_map_flags {
	XRP_MAP_READ,
	XRP_MAP_WRITE,
	XRP_MAP_READ_WRITE,
};


/* Device API. */

/*
 * Open device by index.
 * A device is reference counted and is opened with reference count of 1.
 */
struct xrp_device *xrp_open_device(int idx, enum xrp_status *status);

/*
 * Increment device reference count.
 */
void xrp_retain_device(struct xrp_device *device, enum xrp_status *status);

/*
 * Decrement device reference count (and free associated resources once the
 * counter gets down to zero).
 */
void xrp_release_device(struct xrp_device *device, enum xrp_status *status);


/* Buffer API. */

/*
 * Create memory buffer and allocate device-specific storage (host_ptr == NULL)
 * or use host buffer (host_ptr != NULL, treated as virtual address in the
 * current process).
 * A buffer is reference counted and is created with reference count of 1.
 */
struct xrp_buffer *xrp_create_buffer(struct xrp_device *device,
				     size_t size, void *host_ptr,
				     enum xrp_status *status);

/*
 * Increment buffer reference count.
 */
void xrp_retain_buffer(struct xrp_buffer *buffer, enum xrp_status *status);

/*
 * Decrement buffer reference count (and free the storage if it was allocated
 * once the counter gets down to zero).
 */
void xrp_release_buffer(struct xrp_buffer *buffer, enum xrp_status *status);

/*
 * Map subbuffer of the buffer. Buffer may be mapped multiple times.
 */
void *xrp_map_buffer(struct xrp_buffer *buffer, size_t offset, size_t size,
		     enum xrp_map_flags map_flags, enum xrp_status *status);

/*
 * Unmap previously mapped buffer.
 */
void xrp_unmap_buffer(struct xrp_buffer *buffer, void *p,
		      enum xrp_status *status);


/*
 * Buffer group API.
 */

/*
 * Create a group of shared buffers. Group is reference counted and is
 * created with reference count of 1.
 */
struct xrp_buffer_group *xrp_create_buffer_group(enum xrp_status *status);

/*
 * Decrement group reference count (and free it once the counter gets down
 * to zero).
 */
void xrp_release_buffer_group(struct xrp_buffer_group *group,
			      enum xrp_status *status);

/*
 * Add buffer to the group and get its index.
 * This adds a reference to the buffer.
 * A buffer may be added to at most one group.
 */
int xrp_add_buffer_to_group(struct xrp_buffer_group *group,
			    struct xrp_buffer *buffer,
			    enum xrp_status *status);

/*
 * Get buffer from the group by its index.
 * Buffer must be freed with release_buffer.
 */
struct xrp_buffer *xrp_get_buffer_from_group(struct xrp_buffer_group *group,
					     int idx,
					     enum xrp_status *status);


/*
 * Queue API.
 */

/*
 * Queue is an ordered device communication channel. Queue is reference
 * counted and is created with reference count of 1.
 */
struct xrp_queue *xrp_create_queue(struct xrp_device *device,
				   enum xrp_status *status);

/*
 * Increment queue reference count.
 */
void xrp_retain_queue(struct xrp_queue *queue,
		      enum xrp_status *status);

/*
 * Decrement queue reference count (and free it once the counter gets down
 * to zero).
 */
void xrp_release_queue(struct xrp_queue *queue,
		       enum xrp_status *status);

/*
 * Communication API.
 */
/*
 * Even more internal API related to command passing between cores.
 * These are tightly coupled to the host-DSP communication model and
 * are likely to be changed/enhanced as the model evolves.
 */

/*
 * When this is invoked on host it synchronously runs a command on DSP,
 * passing a group of shared buffers. All buffers in the group must
 * be unmapped at that point.
 */
unsigned xrp_run_command_sync(void *data, size_t data_sz,
			      struct xrp_buffer_group *buffer_group);

/*
 * Get shared buffer group for the current command on DSP.
 * It is only available on the DSP side and only when the host is blocked in
 * the run_command_sync call.
 * Group must be freed with release_buffer_group before command completion
 * and all buffers taken from it must be unmapped and released at that point.
 */
struct xrp_buffer_group *xrp_get_command_buffer_group(void);

void xrp_queue_command(struct xrp_queue *queue,
		       void *data, size_t data_sz,
		       struct xrp_buffer_group *buffer_group,
		       struct xrp_event **evt,
		       enum xrp_status *status);

void xrp_wait(struct xrp_event *event, enum xrp_status *status);

#endif
