#ifndef _XRP_API_H
#define _XRP_API_H

#include <stddef.h>

/*
 * User API.
 */

struct xrp_buffer;
enum xrp_status {
	XRP_STATUS_SUCCESS,
	XRP_STATUS_FAILURE,
};
enum xrp_map_flags {
	XRP_MAP_READ,
	XRP_MAP_WRITE,
	XRP_MAP_READ_WRITE,
};

/*
 * Create memory buffer and allocate shareable storage (host_ptr == NULL) or
 * use host buffer (host_ptr != NULL, treated as virtual address in the
 * current process).
 * A buffer is reference counted and is created with reference count of 1.
 */
struct xrp_buffer *xrp_create_buffer(size_t size, void *host_ptr,
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
 * Internal API.
 */

struct xrp_context;

/*
 * Create a context of shared buffers. Context is reference counted and is
 * created with reference count of 1.
 */
struct xrp_context *xrp_create_context(enum xrp_status *status);

/*
 * Decrement context reference count (and free it once the counter gets down
 * to zero).
 */
void xrp_release_context(struct xrp_context *context, enum xrp_status *status);

/*
 * Add buffer to the context and get its index.
 * This adds a reference to the buffer.
 * A buffer may be added to at most one context.
 */
int xrp_add_buffer_to_context(struct xrp_context *context,
			      struct xrp_buffer *buffer,
			      enum xrp_status *status);

/*
 * Get buffer from the context by its index.
 * Buffer must be freed with release_buffer.
 */
struct xrp_buffer *xrp_get_buffer_from_context(struct xrp_context *context,
					       int idx,
					       enum xrp_status *status);


/*
 * Even more internal API related to command passing between cores.
 * These are tightly coupled to the host-DSP communication model and
 * are likely to be changed/enhanced as the model evolves.
 */

/*
 * When this is invoked on host it synchronously runs a command on DSP,
 * passing a context of shared buffers. All buffers in the context must
 * be unmapped at that point.
 */
unsigned xrp_run_command_sync(void *data, size_t data_sz,
			      struct xrp_context *context);

/*
 * Get shared context for the current command on DSP.
 * It is only available on the DSP side and only when the host is blocked in
 * the run_command_sync call.
 * Context must be freed with release_context before command completion
 * and all buffers taken from it must be unmapped and released at that point.
 */
struct xrp_context *xrp_get_command_context(void);

#endif
