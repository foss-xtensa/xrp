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

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "xrp_debug.h"
#include "xrp_ns.h"

static int compare_cmd_ns(const void *nsid, struct xrp_cmd_ns *cmd_ns)
{
	return memcmp(nsid, cmd_ns->id, sizeof(cmd_ns->id));
}

int xrp_cmd_ns_match(const void *nsid, struct xrp_cmd_ns *cmd_ns)
{
	return cmd_ns && compare_cmd_ns(nsid, cmd_ns) == 0;
}

#ifdef DEBUG
static void dump_nsid(const void *p)
{
	const uint8_t *id = p;

	printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	       id[0], id[1], id[2], id[3],
	       id[4], id[5],
	       id[6], id[7],
	       id[8], id[9],
	       id[10], id[11], id[12], id[13], id[14], id[15]);
}

static void dump_cmd_ns(const struct xrp_cmd_ns *cmd_ns)
{
	if (cmd_ns) {
		dump_nsid(cmd_ns->id);
		printf(" -> %p(%p)", cmd_ns->handler, cmd_ns->handler_context);
	} else {
		printf("NULL");
	}
}

static void dump_cmd_ns_map(const struct xrp_cmd_ns_map *ns_map)
{
	size_t i;

	printf("n_cmd_ns: %zu, size_cmd_ns: %zu\n",
	       ns_map->n_cmd_ns, ns_map->size_cmd_ns);
	for (i = 0; i < ns_map->n_cmd_ns; ++i) {
		printf("  ");
		dump_cmd_ns(ns_map->cmd_ns + i);
		printf("\n");
	}
}
#else
static void dump_nsid(const void *p)
{
	(void)p;
}

static void dump_cmd_ns(const struct xrp_cmd_ns *cmd_ns)
{
	(void)cmd_ns;
}

static void dump_cmd_ns_map(const struct xrp_cmd_ns_map *ns_map)
{
	(void)ns_map;
}
#endif

static int cmd_ns_present(struct xrp_cmd_ns_map *ns_map,
			  struct xrp_cmd_ns *cmd_ns)
{
	return cmd_ns >= ns_map->cmd_ns &&
		cmd_ns < ns_map->cmd_ns + ns_map->n_cmd_ns;
}

struct xrp_cmd_ns *xrp_find_cmd_ns(struct xrp_cmd_ns_map *ns_map,
				   const void *id)
{
	size_t a = 0;
	size_t b = ns_map->n_cmd_ns;
	struct xrp_cmd_ns *p;

	pr_debug("%s: ", __func__);
	dump_nsid(id);
	pr_debug("\n");
	while (b - a > 1) {
		size_t c = (a + b) / 2;

		pr_debug("a: %zu, b:%zu, c: %zu\n", a, b, c);
		p = ns_map->cmd_ns + c;
		if (compare_cmd_ns(id, p) < 0)
			b = c;
		else
			a = c;
		pr_debug("...a: %zu, b:%zu\n", a, b);
	}
	p = ns_map->cmd_ns + a;
	if (a < b && compare_cmd_ns(id, p) > 0)
		++p;
	if (cmd_ns_present(ns_map, p)) {
		pr_debug("%s: found: ", __func__);
		dump_cmd_ns(p);
		pr_debug("\n");
	} else {
		pr_debug("%s: not found\n", __func__);
	}

	return p;
}

static struct xrp_cmd_ns *insert_cmd_ns(struct xrp_cmd_ns_map *ns_map,
					struct xrp_cmd_ns *cmd_ns)
{
	size_t i = cmd_ns - ns_map->cmd_ns;

	if (ns_map->n_cmd_ns == ns_map->size_cmd_ns) {
		size_t new_size = (ns_map->size_cmd_ns + 1) * 2;
		void *new_cmd_ns = realloc(ns_map->cmd_ns,
					   new_size * sizeof(*ns_map->cmd_ns));

		if (!new_cmd_ns)
			return NULL;
		ns_map->cmd_ns = new_cmd_ns;
		ns_map->size_cmd_ns = new_size;
		cmd_ns = ns_map->cmd_ns + i;
	}
	memmove(cmd_ns + 1, cmd_ns,
		sizeof(*cmd_ns) * (ns_map->n_cmd_ns - i));
	++ns_map->n_cmd_ns;
	return cmd_ns;
}

static void remove_cmd_ns(struct xrp_cmd_ns_map *ns_map,
			  struct xrp_cmd_ns *cmd_ns)
{
	size_t i = cmd_ns - ns_map->cmd_ns;

	memmove(cmd_ns, cmd_ns + 1,
		sizeof(*cmd_ns) * (ns_map->n_cmd_ns - i - 1));
	--ns_map->n_cmd_ns;
}

int xrp_register_namespace(struct xrp_cmd_ns_map *ns_map,
			   const void *nsid,
			   xrp_command_handler *handler,
			   void *handler_context)
{
	struct xrp_cmd_ns *cmd_ns = xrp_find_cmd_ns(ns_map, nsid);

	if (cmd_ns_present(ns_map, cmd_ns) && xrp_cmd_ns_match(nsid, cmd_ns)) {
		return 0;
	} else {
		cmd_ns = insert_cmd_ns(ns_map, cmd_ns);
		if (cmd_ns) {
			memcpy(cmd_ns->id, nsid, sizeof(cmd_ns->id));
			cmd_ns->handler = handler;
			cmd_ns->handler_context = handler_context;
			dump_cmd_ns_map(ns_map);
			return 1;
		} else {
			return 0;
		}
	}
}

int xrp_unregister_namespace(struct xrp_cmd_ns_map *ns_map,
			     const void *nsid)
{
	struct xrp_cmd_ns *cmd_ns = xrp_find_cmd_ns(ns_map, nsid);

	if (cmd_ns_present(ns_map, cmd_ns) && xrp_cmd_ns_match(nsid, cmd_ns)) {
		remove_cmd_ns(ns_map, cmd_ns);
		dump_cmd_ns_map(ns_map);
		return 1;
	} else {
		return 0;
	}
}
