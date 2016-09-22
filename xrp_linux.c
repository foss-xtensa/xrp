#include "xrp_api.h"


struct xrp_buffer {
	void *p;
};

struct xrp_buffer *xrp_create_buffer(size_t size, void *host_ptr,
				     enum xrp_status *status)
{
	return NULL;
}

void xrp_retain_buffer(struct xrp_buffer *buffer, enum xrp_status *status)
{
}

void xrp_release_buffer(struct xrp_buffer *buffer, enum xrp_status *status)
{
}

void *xrp_map_buffer(struct xrp_buffer *buffer, size_t offset, size_t size,
		     enum xrp_map_flags map_flags, enum xrp_status *status)
{
	return NULL;
}

void xrp_unmap_buffer(struct xrp_buffer *buffer, void *p,
		      enum xrp_status *status)
{
}

/* internal API */

struct xrp_context {
	size_t n_buffers;
	struct xrp_buffer *buffer;
};

struct xrp_context *xrp_create_context(enum xrp_status *status)
{
	return NULL;
}

void xrp_release_context(struct xrp_context *context,
			 enum xrp_status *status)
{
}

int xrp_add_buffer_to_context(struct xrp_context *context,
			      struct xrp_buffer *buffer,
			      enum xrp_status *status)
{
	return 0;
}

struct xrp_buffer *xrp_get_buffer_from_context(struct xrp_context *context,
					       int idx,
					       enum xrp_status *status)
{
	return NULL;
}
