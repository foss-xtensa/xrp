/*
 * Copyright (c) 2016 - 2018 Cadence Design Systems Inc.
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

#ifndef _XRP_NS_H
#define _XRP_NS_H

#include <xrp_api.h>

struct xrp_cmd_ns {
	char id[XRP_NAMESPACE_ID_SIZE];
	xrp_command_handler *handler;
	void *handler_context;
};

struct xrp_cmd_ns_map {
	size_t n_cmd_ns;
	size_t size_cmd_ns;
	struct xrp_cmd_ns *cmd_ns;
};

int xrp_register_namespace(struct xrp_cmd_ns_map *ns_map,
			   const void *nsid,
			   xrp_command_handler *handler,
			   void *handler_context);
int xrp_unregister_namespace(struct xrp_cmd_ns_map *ns_map,
			     const void *nsid);

int xrp_cmd_ns_match(const void *nsid, struct xrp_cmd_ns *cmd_ns);
struct xrp_cmd_ns *xrp_find_cmd_ns(struct xrp_cmd_ns_map *ns_map,
				   const void *id);

#endif
