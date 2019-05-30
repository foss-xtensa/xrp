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

/*!
 * \file xrp_api.h
 * \brief This section defines XRP API.
 *
 * General API properties:
 * - All status pointers can be NULL.
 * - Reference counting is not meant to work across host/DSP boundary, i.e.
 *   DSP may not retain the host buffer.
 * - A buffer allocated for one device can be passed as command parameter to
 *   a different device; implementation should do reasonable thing, e.g. use
 *   the original data if possible or transparently migrate it to suitable
 *   memory.
 * - A group of API calls may be host side only, DSP side only, or usable on
 *   both sides. When it's usable on both sides there may be additional
 *   restrictions on the DSP side.
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

/*!
 * Status codes of XRP calls.
 */
enum xrp_status {
	/*! Call completed successfully. */
	XRP_STATUS_SUCCESS,
	/*! Call failed. */
	XRP_STATUS_FAILURE,
	/*! Call has not completed. */
	XRP_STATUS_PENDING,
};
enum xrp_access_flags {
	XRP_READ		= 0x1,
	XRP_WRITE		= 0x2,
	XRP_READ_WRITE		= 0x3,
};

/*!
 * Types of information that may be queried for a buffer object.
 */
enum xrp_buffer_info {
	/*! Size of the buffer. */
	XRP_BUFFER_SIZE_SIZE_T,
	/*! Host pointer of the buffer. */
	XRP_BUFFER_HOST_POINTER_PTR,
};

/*!
 * Types of information that may be queried for a buffer group object.
 */
enum xrp_buffer_group_info {
	/*! Access flags associated with a buffer. Requires buffer index. */
	XRP_BUFFER_GROUP_BUFFER_FLAGS_ENUM,
	/*! Number of buffers in the buffer group. Buffer index is ignored. */
	XRP_BUFFER_GROUP_SIZE_SIZE_T,
};

#define XRP_NAMESPACE_ID_SIZE	16

/*!
 * \defgroup device_api Device API
 * These calls are available on the host side and on the DSP side with the
 * following restriction:
 * - only device 0 may be opened.
 * @{
 */

/*!
 * Open device by index.
 * A device is reference counted and is opened with reference count of 1.
 * Devices are numbered sequentially starting at 0, they can be probed with
 * simple loop.
 * \param idx: device index to open
 * \param[out] status: operation status
 * \return pointer to the opened device or NULL in case of error
 */
struct xrp_device *xrp_open_device(int idx, enum xrp_status *status);

/*!
 * Increment device reference count.
 */
void xrp_retain_device(struct xrp_device *device);

/*!
 * Decrement device reference count (and free associated resources once the
 * counter gets down to zero).
 */
void xrp_release_device(struct xrp_device *device);

/*!
 * @}
 */

/*!
 * \defgroup buffer_api Buffer API
 * These calls are available on the host side and on the DSP side with the
 * following restriction:
 * - buffers may not be created on the DSP side.
 * @{
 */

/*!
 * Create memory buffer and allocate device-specific storage (host_ptr == NULL)
 * or use host buffer (host_ptr != NULL, treated as virtual address in the
 * current process).
 * A buffer is reference counted and is created with reference count of 1.
 * \param[out] status: operation status
 */
struct xrp_buffer *xrp_create_buffer(struct xrp_device *device,
				     size_t size, void *host_ptr,
				     enum xrp_status *status);

/*!
 * Increment buffer reference count.
 */
void xrp_retain_buffer(struct xrp_buffer *buffer);

/*!
 * Decrement buffer reference count (and free the storage if it was allocated
 * once the counter gets down to zero).
 */
void xrp_release_buffer(struct xrp_buffer *buffer);

/*!
 * Map subbuffer of the buffer. Buffer may be mapped multiple times.
 *
 * \param map_flags: access to the mapping requested by the mapper. Access
 * to buffers on DSP side is subject to restrictions set by the host side.
 * \param[out] status: operation status
 */
void *xrp_map_buffer(struct xrp_buffer *buffer, size_t offset, size_t size,
		     enum xrp_access_flags map_flags, enum xrp_status *status);

/*!
 * Unmap previously mapped buffer.
 * \param[out] status: operation status
 */
void xrp_unmap_buffer(struct xrp_buffer *buffer, void *p,
		      enum xrp_status *status);

/*!
 * Get information about the buffer object.
 *
 * \param info: information type to retrieve.
 * \param[out] out: pointer to return information to.
 * \param out_sz: size of out buffer.
 * \param[out] status: operation status
 */
void xrp_buffer_get_info(struct xrp_buffer *buffer, enum xrp_buffer_info info,
			 void *out, size_t out_sz, enum xrp_status *status);

/*!
 * @}
 */

/*!
 * \defgroup buffer_group_api Buffer Group API
 * These calls are available on the host side and on the DSP side with the
 * following restrictions:
 * - buffer groups may not be created on the DSP side;
 * - existing buffer groups may not be modified on the DSP side.
 * @{
 */

/*!
 * Create a group of shared buffers. Group is reference counted and is
 * created with reference count of 1.
 * \param[out] status: operation status
 */
struct xrp_buffer_group *xrp_create_buffer_group(enum xrp_status *status);

/*!
 * Increment buffer group reference count.
 */
void xrp_retain_buffer_group(struct xrp_buffer_group *group);

/*!
 * Decrement group reference count (and free it once the counter gets down
 * to zero).
 */
void xrp_release_buffer_group(struct xrp_buffer_group *group);

/*!
 * Add buffer to the group and get its index.
 * This adds a reference to the buffer.
 *
 * \param access_flags: granted access. User of the buffer on the DSP side
 * will be able to map it only for this type of access.
 * \param[out] status: operation status
 */
size_t xrp_add_buffer_to_group(struct xrp_buffer_group *group,
			       struct xrp_buffer *buffer,
			       enum xrp_access_flags access_flags,
			       enum xrp_status *status);

/*!
 * Put new buffer to the existing index in the group.
 * When operation succeeds it releases the buffer previously contained at
 * that index and adds a reference to the new buffer.
 *
 * \param access_flags: granted access. User of the buffer on the DSP side
 * will be able to map it only for this type of access.
 * \param[out] status: operation status
 */
void xrp_set_buffer_in_group(struct xrp_buffer_group *group,
			     size_t index,
			     struct xrp_buffer *buffer,
			     enum xrp_access_flags access_flags,
			     enum xrp_status *status);

/*!
 * Get buffer from the group by its index.
 * Buffer must be freed with release_buffer.
 * \param[out] status: operation status
 */
struct xrp_buffer *xrp_get_buffer_from_group(struct xrp_buffer_group *group,
					     size_t idx,
					     enum xrp_status *status);

/*!
 * Get information about the buffer group object.
 *
 * \param info: information type to retrieve.
 * \param idx: buffer index (if applicable).
 * \param[out] out: pointer to return information to.
 * \param out_sz: size of out buffer.
 * \param[out] status: operation status
 */
void xrp_buffer_group_get_info(struct xrp_buffer_group *group,
			       enum xrp_buffer_group_info info, size_t idx,
			       void *out, size_t out_sz,
			       enum xrp_status *status);

/*!
 * @}
 */

/*!
 * \defgroup queue_api Queue API
 * These calls are available only on the host side.
 * @{
 */

/*!
 * Create queue to the default namespace of the device.
 * Queue is an ordered device communication channel. Queue is reference
 * counted and is created with reference count of 1.
 * \param[out] status: operation status
 */
struct xrp_queue *xrp_create_queue(struct xrp_device *device,
				   enum xrp_status *status);

/*!
 * Create queue to the specified namespace of the device.
 * Queue is an ordered device communication channel. Queue is reference
 * counted and is created with reference count of 1.
 * \param[out] status: operation status
 */
struct xrp_queue *xrp_create_ns_queue(struct xrp_device *device,
				      const void *nsid,
				      enum xrp_status *status);

/*!
 * Create queue to the specified namespace of the device with specific
 * priority.
 * Queue is an ordered device communication channel. Queue is reference
 * counted and is created with reference count of 1.
 * \param[out] status: operation status
 */
struct xrp_queue *xrp_create_nsp_queue(struct xrp_device *device,
				       const void *nsid,
				       int priority,
				       enum xrp_status *status);

/*!
 * Increment queue reference count.
 */
void xrp_retain_queue(struct xrp_queue *queue);

/*!
 * Decrement queue reference count (and free it once the counter gets down
 * to zero).
 */
void xrp_release_queue(struct xrp_queue *queue);

/*!
 * @}
 */

/*!
 * \defgroup event_api Event API
 * These calls are available only on the host side.
 * @{
 */

/*!
 * Increment event reference count.
 */
void xrp_retain_event(struct xrp_event *event);

/*!
 * Decrement event reference count (and free it once the counter gets down
 * to zero).
 */
void xrp_release_event(struct xrp_event *event);


/*!
 * Get status of the event/associated command.
 * The function may be called at any time, it sets *status to
 * XRP_STATUS_PENDING if the command has not been executed yet, or to the
 * command execution status. See status description of xrp_run_command_sync()
 * for the description of command execution status.
 * \param[out] status: operation status
 */
void xrp_event_status(struct xrp_event *event, enum xrp_status *status);

/*!
 * @}
 */

/*!
 * \defgroup communication_api Communication API
 * These calls are available only on the host side.
 * @{
 */

/*
 * Even more internal API related to command passing between cores.
 * These are tightly coupled to the host-DSP communication model and
 * are likely to be changed/enhanced as the model evolves.
 */

/*!
 * Synchronously send command from host to DSP.
 *
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
 * status is the result of command execution. Command execution is
 * successful if the command was delivered to the DSP and the response was
 * delivered back. Otherwise the command execution has failed. IOW execution
 * success means that the out_data contains command-specific response received
 * from the DSP, execution failure means that out_data does not contain useful
 * information.
 *
 * \param[out] status: operation status
 */
void xrp_run_command_sync(struct xrp_queue *queue,
			  const void *in_data, size_t in_data_size,
			  void *out_data, size_t out_data_size,
			  struct xrp_buffer_group *buffer_group,
			  enum xrp_status *status);

/*!
 * Asynchronously send command from host to DSP.
 *
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
 * If event is non-NULL then a pointer to an event corresponding to the
 * queued command is returned. This event can be waited for with xrp_wait,
 * it is signaled when the command execution is complete.
 * The returned event object is reference counted and is created with
 * reference count of 1.
 *
 * status is the result of command enqueuing. Command enqueuing is
 * successful if the command was enqueued on the host side and an associated
 * event has been returned (if requested). Otherwise the command enqueuing has
 * failed. IOW enqueuing success means that if event is non-NULL then *event
 * contains valid event, enqueuing failure means that *event does not contain
 * useful information.
 *
 * \param[out] status: operation status
 */
void xrp_enqueue_command(struct xrp_queue *queue,
			 const void *in_data, size_t in_data_size,
			 void *out_data, size_t out_data_size,
			 struct xrp_buffer_group *buffer_group,
			 struct xrp_event **event,
			 enum xrp_status *status);

/*!
 * Wait for the event.
 * Waiting for already signaled event completes immediately.
 * Successful completion of this function does not alter the event state,
 * i.e. the event remains signaled.
 * status is the result of waiting, not the result of the command execution.
 * Use xrp_event_status() to get the command execution status.
 * \param[out] status: operation status
 */
void xrp_wait(struct xrp_event *event, enum xrp_status *status);

/*!
 * Wait for any event in the group.
 * Waiting for a group with already signaled event completes immediately.
 * Successful completion of this function does not alter the event state,
 * i.e. signaled events remain signaled.
 * status is the result of waiting, not the result of the command execution.
 * Use xrp_event_status() with individual events to get the corresponding
 * command execution status.
 *
 * \param[in] event: an array of pointers to events to wait for
 * \param[i] n_events: number of events in the events array
 * \param[out] status: operation status
 * \return index of a completed event in the event array
 */
size_t xrp_wait_any(struct xrp_event **event, size_t n_events,
		    enum xrp_status *status);

/*!
 * @}
 */

/*!
 * \defgroup dsp_specific_api DSP-specific Interface (Library-Style)
 * These calls are available only on the DSP side.
 * @{
 */

/*!
 * Check if there's a command from the host in the hardware queue.
 * Returns XRP_STATUS_PENDING if the queue is empty or XRP_STATUS_SUCCESS
 * if there is a command ready for processing.
 *
 * The check is quick and may be issued in any context.
 */
enum xrp_status xrp_device_poll(struct xrp_device *device);

/*!
 * Check if there's a command from the host in the hardware queue and invoke
 * command handler if there's one.
 * Returns XRP_STATUS_PENDING if the queue is empty, or the status returned by
 * the command handler.
 */
enum xrp_status xrp_device_dispatch(struct xrp_device *device);

/*!
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

/*!
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
 * \param[out] status: operation status
 */
void xrp_device_register_namespace(struct xrp_device *device,
				   const void *nsid,
				   xrp_command_handler *handler,
				   void *handler_context,
				   enum xrp_status *status);

/*!
 * Unregister namespace handler.
 *
 * Only registered namespace handler may be unregistered.
 *
 * \param device: device for which namespace handler is registered
 * \param nsid: namespace identifier, XRP_NAMESPACE_ID_SIZE bytes long
 * \param[out] status: operation status
 */
void xrp_device_unregister_namespace(struct xrp_device *device,
				     const void *nsid,
				     enum xrp_status *status);

/*!
 * Enable or disable shared memory cache management.
 * Note that this call does not change memory caching attributes, it only
 * enables flushing and invalidating used regions of shared memory in the
 * XRP code.
 *
 * \param device: device for which shared memory cache management state is
 *                changed
 * \param enable: whether cache management shall be enabled (non-zero) or
 *                disabled (0)
 */
void xrp_device_enable_cache(struct xrp_device *device, int enable);

/*!
 * @}
 */

/*!
 * Helper function that terminates fast simulation.
 */
void xrp_exit(void);

#ifdef __cplusplus
}
#endif

#endif
