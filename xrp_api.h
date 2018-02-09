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

#ifndef _XRP_API_H
#define _XRP_API_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

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
	XRP_STATUS_PENDING,
};
enum xrp_access_flags {
	XRP_READ		= 0x1,
	XRP_WRITE		= 0x2,
	XRP_READ_WRITE		= 0x3,
};
enum xrp_buffer_info {
	XRP_BUFFER_SIZE_SIZE_T,
	XRP_BUFFER_HOST_POINTER_PTR,
};
enum xrp_buffer_group_info {
	XRP_BUFFER_GROUP_BUFFER_FLAGS_ENUM,
	XRP_BUFFER_GROUP_SIZE_SIZE_T,
};

#define XRP_NAMESPACE_ID_SIZE	16

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
 * Get information about the buffer object.
 *
 * \param info: information type to retrieve.
 * \param out: pointer to return information to.
 * \param out_sz: size of out buffer.
 */
void xrp_buffer_get_info(struct xrp_buffer *buffer, enum xrp_buffer_info info,
			 void *out, size_t out_sz, enum xrp_status *status);


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
 *
 * \param access_flags: granted access. User of the buffer on the DSP side
 * will be able to map it only for this type of access.
 */
size_t xrp_add_buffer_to_group(struct xrp_buffer_group *group,
			       struct xrp_buffer *buffer,
			       enum xrp_access_flags access_flags,
			       enum xrp_status *status);

/*
 * Put new buffer to the existing index in the group.
 * When operation succeeds it releases the buffer previously contained at
 * that index and adds a reference to the new buffer.
 *
 * \param access_flags: granted access. User of the buffer on the DSP side
 * will be able to map it only for this type of access.
 */
void xrp_set_buffer_in_group(struct xrp_buffer_group *group,
			     size_t index,
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
 * Get information about the buffer group object.
 *
 * \param info: information type to retrieve.
 * \param idx: buffer index (if applicable).
 * \param out: pointer to return information to.
 * \param out_sz: size of out buffer.
 */
void xrp_buffer_group_get_info(struct xrp_buffer_group *group,
			       enum xrp_buffer_group_info info, size_t idx,
			       void *out, size_t out_sz,
			       enum xrp_status *status);


/*
 * Queue API.
 */

/*
 * Create queue to the default namespace of the device.
 * Queue is an ordered device communication channel. Queue is reference
 * counted and is created with reference count of 1.
 */
struct xrp_queue *xrp_create_queue(struct xrp_device *device,
				   enum xrp_status *status);

/*
 * Create queue to the specified namespace of the device.
 * Queue is an ordered device communication channel. Queue is reference
 * counted and is created with reference count of 1.
 */
struct xrp_queue *xrp_create_ns_queue(struct xrp_device *device,
				      const void *nsid,
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
 * Get status of the event/associated command.
 * The function may be called at any time, it sets *status to
 * XRP_STATUS_PENDING if the command has not been executed yet, or to the
 * command execution status. See status description of xrp_run_command_sync
 * for the description of command execution status.
 */
void xrp_event_status(struct xrp_event *event, enum xrp_status *status);

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
 *
 * status is the result of command execution. Command execution is
 * successfull if the command was delivered to the DSP and the response was
 * delivered back. Otherwise the command execution is failed. IOW execution
 * success means that the out_data contains command-specific response received
 * from the DSP, execution failure means that out_data does not contain useful
 * information.
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
 *
 * status is the result of command enqueuing. Command enqueuing is
 * successfull if the command was enqueued on the host side and an associated
 * event has been returned (if requested). Otherwise the command execution is
 * failed. IOW enqueuing success means that if event is non-NULL then *event
 * contains valid event, enqueuing failure means that *event does not contain
 * useful information.
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
 * status is the result of waiting, not the result of the command execution.
 * Use xrp_event_status to get the command execution status.
 */
void xrp_wait(struct xrp_event *event, enum xrp_status *status);


/* New DSP-specific interface (library-style) */

/*
 * Check if there's a command from the host in the hardware queue.
 * Returns XRP_STATUS_PENDING if the queue is empty or XRP_STATUS_SUCCESS
 * if there is a command ready for processing.
 *
 * The check is quick and may be issued in any context.
 */
enum xrp_status xrp_device_poll(struct xrp_device *device);

/*
 * Check if there's a command from the host in the hardware queue and invoke
 * command handler if there's one.
 * Returns XRP_STATUS_PENDING if the queue is empty, or the status returned by
 * the command handler.
 */
enum xrp_status xrp_device_dispatch(struct xrp_device *device);

/*
 * Function type for command handler.
 *
 * This callback is called on the DSP side to process queued command.
 * in_data, out_data and buffer_group correspond to the same parameters of the
 * host side API calls.
 *
 * On return from this function buffer group and individual buffer reference
 * counters shall be restored to their entry values. out_data buffer shall be
 * updated with command return value.
 * Neither in_data nor out_data may be referenced after this function returns.
 *
 * Return value shall describe whether xrp_command_handler itself was
 * successful or not, not the command it was requested to run.
 * I.e. if the command was not recognized or its handler could not be called
 * due to insufficient memory, that's XRP_STATUS_FAILURE returned in status.
 * The host will also receive XRP_STATUS_FAILURE as a completion status.
 * If the command was run that's XRP_STATUS_SUCCESS regardless of the
 * command-specific status, which should be returned in out_data.
 *
 * \param handler_context: context that was passed to the
 *                         xrp_device_register_namespace
 */
typedef enum xrp_status
(xrp_command_handler)(void *handler_context,
		      const void *in_data, size_t in_data_size,
		      void *out_data, size_t out_data_size,
		      struct xrp_buffer_group *buffer_group);

/*
 * Register namespace handler.
 *
 * There may be only one handler for a namespace, second attempt to register
 * a handler for the same namespace will fail.
 *
 * \param device: device for which namespace handler is registered
 * \param nsid: namespace identifier, XRP_NAMESPACE_ID_SIZE bytes long
 * \param handler: pointer to the handler function
 * \param handler_context: first argument that will be passed to the handler
 *                         function
 * \param status: status of the registration operation
 */
void xrp_device_register_namespace(struct xrp_device *device,
				   const void *nsid,
				   xrp_command_handler *handler,
				   void *handler_context,
				   enum xrp_status *status);

/*
 * Unregister namespace handler.
 *
 * Only registered namespace handler may be unregistered.
 *
 * \param device: device for which namespace handler is registered
 * \param nsid: namespace identifier, XRP_NAMESPACE_ID_SIZE bytes long
 * \param status: status of the unregistration operation
 */
void xrp_device_unregister_namespace(struct xrp_device *device,
				     const void *nsid,
				     enum xrp_status *status);


/* Legacy DSP-specific interface (framework-style) */

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

/*
 * Helper function that terminates fast simulation
 */
void xrp_exit(void);

#ifdef __cplusplus
}
#endif

#endif
