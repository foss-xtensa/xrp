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
enum xrp_access_flags {
	XRP_READ		= 0x1,
	XRP_WRITE		= 0x2,
	XRP_READ_WRITE		= 0x3,
};

/*
 * General notes:
 * - all status pointers can be NULL;
 * - reference counting is not meant to work across host/DSP boundary, i.e.
 *   DSP may not retain the host buffer;
 * - a buffer allocated for one device can be passed as command parameter to
 *   a different device; implementation should do reasonable thing, e.g. use
 *   the original data if possible or transparently migrate it to suitable
 *   memory;
 * - a group of API calls may be host side only, DSP side only, or usable on
 *   both sides. When it's usable on both sides there may be additional
 *   restrictions on the DSP side.
 */

/*
 * Device API.
 */

/*
 * Open device by index.
 * A device is reference counted and is opened with reference count of 1.
 * Devices are numbered sequentially starting at 0, they can be probed with
 * simple loop.
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


/*
 * Buffer API.
 * Available on both host and DSP side.
 */

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
 *
 * \param map_flags: access to the mapping requested by the mapper. Access
 * to buffers on DSP side is subject to restrictions set by the host side.
 */
void *xrp_map_buffer(struct xrp_buffer *buffer, size_t offset, size_t size,
		     enum xrp_access_flags map_flags, enum xrp_status *status);

/*
 * Unmap previously mapped buffer.
 */
void xrp_unmap_buffer(struct xrp_buffer *buffer, void *p,
		      enum xrp_status *status);


/*
 * Buffer group API.
 * Available on both host and DSP side.
 */

/*
 * Create a group of shared buffers. Group is reference counted and is
 * created with reference count of 1.
 */
struct xrp_buffer_group *xrp_create_buffer_group(enum xrp_status *status);

/*
 * Increment buffer group reference count.
 */
void xrp_retain_buffer_group(struct xrp_buffer_group *group,
			     enum xrp_status *status);

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
 *
 * \param access_flags: granted access. User of the buffer on the DSP side
 * will be able to map it only for this type of access.
 */
size_t xrp_add_buffer_to_group(struct xrp_buffer_group *group,
			       struct xrp_buffer *buffer,
			       enum xrp_access_flags access_flags,
			       enum xrp_status *status);

/*
 * Get buffer from the group by its index.
 * Buffer must be freed with release_buffer.
 */
struct xrp_buffer *xrp_get_buffer_from_group(struct xrp_buffer_group *group,
					     size_t idx,
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
 * Event API.
 */

/*
 * Increment event reference count.
 */
void xrp_retain_event(struct xrp_event *event,
		      enum xrp_status *status);

/*
 * Decrement event reference count (and free it once the counter gets down
 * to zero).
 */
void xrp_release_event(struct xrp_event *event,
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
 * When this is invoked on the host it synchronously runs a command on DSP,
 * passing a group of shared buffers and two additional (small) buffers
 * with opaque command description (in_data) and results (out_data).
 *
 * in_data is used at the function call and is not referenced afterwards.
 * out_data is updated with the value returned by DSP before the function
 * returns.
 *
 * Optimal processing is guaranteed for in_data and out_data buffers not
 * exceeding 16 bytes in size. Larger buffers may require additional data
 * copying depending on the implementation.
 *
 * All buffers in the passed group must be unmapped at that point.
 */
void xrp_run_command_sync(struct xrp_queue *queue,
			  const void *in_data, size_t in_data_size,
			  void *out_data, size_t out_data_size,
			  struct xrp_buffer_group *buffer_group,
			  enum xrp_status *status);

/*
 * When this is invoked on the host it queues a command to DSP,
 * passing a group of shared buffers and two additional (small) buffers
 * with opaque command description (in_data) and results (out_data).
 *
 * in_data is used at the function call and is not referenced afterwards.
 * out_data must stay valid after this function call until command completion,
 * at which point it is updated with the value returned by DSP.
 *
 * Optimal processing is guaranteed for in_data and out_data buffers not
 * exceeding 16 bytes in size. Larger buffers may require additional data
 * copying depending on the implementation.
 *
 * All buffers in the passed group must be unmapped at that point.
 *
 * If event is non-NULL then a pointer to an event corresponding to the
 * queued command is returned. This event can be waited for with xrp_wait,
 * it is signaled when the command execution is complete.
 * The returned event object is reference counted and is created with
 * reference count of 1.
 */
void xrp_enqueue_command(struct xrp_queue *queue,
			 const void *in_data, size_t in_data_size,
			 void *out_data, size_t out_data_size,
			 struct xrp_buffer_group *buffer_group,
			 struct xrp_event **event,
			 enum xrp_status *status);

/*
 * Wait for the event.
 * Waiting for already signaled event completes immediately.
 * Successful completion of this function does not alter the event state,
 * i.e. the event remains signaled.
 */
void xrp_wait(struct xrp_event *event, enum xrp_status *status);


/*
 * DSP side callbacks.
 */

/*
 * Optional initialization callback.
 */
void xrp_user_initialize(enum xrp_status *status);

/*
 * This callback is called on the DSP side to process queued command.
 * in_data, out_data and buffer_group correspond to the same parameters of the
 * host side API calls.
 *
 * On return from this function buffer group and individual buffer reference
 * counters shall be restored to their entry values. out_data buffer shall be
 * updated with command return value.
 * Neither in_data nor out_data may be referenced after this function returns.
 *
 * Value returned in status shall describe whether xrp_run_command itself was
 * successful or not, not the command it was requested to run.
 * I.e. if the command was not recognized or its handler could not be called
 * due to insufficient memory, that's XRP_STATUS_FAILURE returned in status.
 * If the command was run that's XRP_STATUS_SUCCESS regardless of the
 * command-specific status, which should be returned in out_data.
 */
void xrp_run_command(const void *in_data, size_t in_data_size,
		     void *out_data, size_t out_data_size,
		     struct xrp_buffer_group *buffer_group,
		     enum xrp_status *status);

#endif
