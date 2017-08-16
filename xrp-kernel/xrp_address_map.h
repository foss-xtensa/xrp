/*
 * xrp_address_map: CPU->DSP physical address translator
 *
 * Copyright (c) 2017 Cadence Design Systems, Inc.
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
 *
 * Alternatively you can use and distribute this file under the terms of
 * the GNU General Public License version 2 or later.
 */

#ifndef XRP_ADDRESS_MAP_H
#define XRP_ADDRESS_MAP_H

#include <linux/types.h>

#define XRP_NO_TRANSLATION ((u32)~0ul)

struct xrp_address_map_entry {
	phys_addr_t src_addr;
	u32 dst_addr;
	u32 size;
};

struct xrp_address_map {
	unsigned n;
	struct xrp_address_map_entry *entry;
};

int xrp_init_address_map(struct device *dev,
			 struct xrp_address_map *map);

void xrp_free_address_map(struct xrp_address_map *map);

struct xrp_address_map_entry *
xrp_get_address_mapping(const struct xrp_address_map *map, phys_addr_t addr);

u32 xrp_translate_to_dsp(const struct xrp_address_map *map, phys_addr_t addr);

static inline int xrp_compare_address(phys_addr_t addr,
				      const struct xrp_address_map_entry *entry)
{
	if (addr < entry->src_addr)
		return -1;
	if (addr - entry->src_addr < entry->size)
		return 0;
	return 1;
}

#endif
