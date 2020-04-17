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

#include <linux/bsearch.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include "xrp_address_map.h"

static int xrp_compare_address_sort(const void *a, const void *b)
{
	const struct xrp_address_map_entry *pa = a;
	const struct xrp_address_map_entry *pb = b;

	if (pa->src_addr < pb->src_addr &&
	    pb->src_addr - pa->src_addr >= pa->size)
		return -1;
	if (pa->src_addr > pb->src_addr &&
	    pa->src_addr - pb->src_addr >= pb->size)
		return 1;
	return 0;
}

int xrp_init_address_map(struct device *dev,
			 struct xrp_address_map *map)
{
	int ret = 0;
#if IS_ENABLED(CONFIG_OF)
	struct device_node *pnode = dev->of_node;
	struct device_node *node;
	int rlen, off;
	const __be32 *ranges = of_get_property(pnode, "ranges", &rlen);
	int na, pna, ns;
	int i;

	if (!ranges) {
		dev_dbg(dev, "%s: no 'ranges' property in the device tree, no translation at that level\n",
			__func__);
		goto empty;
	}

	node = of_get_next_child(pnode, NULL);
	if (!node) {
		dev_warn(dev, "%s: no child node found in the device tree, no translation at that level\n",
			 __func__);
		goto empty;
	}

	na = of_n_addr_cells(node);
	ns = of_n_size_cells(node);
	pna = of_n_addr_cells(pnode);

	rlen /= 4;
	map->n = rlen / (na + pna + ns);
	map->entry = kmalloc_array(map->n, sizeof(*map->entry), GFP_KERNEL);
	if (!map->entry) {
		ret = -ENOMEM;
		goto err;
	}
	dev_dbg(dev,
		"%s: na = %d, pna = %d, ns = %d, rlen = %d cells, n = %d\n",
		__func__, na, pna, ns, rlen, map->n);

	for (off = 0, i = 0; off < rlen; off += na + pna + ns, ++i) {
		map->entry[i].src_addr = of_translate_address(node,
							      ranges + off);
		map->entry[i].dst_addr = of_read_number(ranges + off, na);
		map->entry[i].size = of_read_number(ranges + off + na + pna,
						    ns);
		dev_dbg(dev,
			"  src_addr = 0x%llx, dst_addr = 0x%lx, size = 0x%lx\n",
			(unsigned long long)map->entry[i].src_addr,
			(unsigned long)map->entry[i].dst_addr,
			(unsigned long)map->entry[i].size);
	}
	sort(map->entry, map->n, sizeof(*map->entry),
	     xrp_compare_address_sort, NULL);
err:
	of_node_put(node);
	return ret;

empty:
#endif
	map->n = 1;
	map->entry = kmalloc(sizeof(*map->entry), GFP_KERNEL);
	map->entry->src_addr = 0;
	map->entry->dst_addr = 0;
	map->entry->size = (u32)~0ul;
	return ret;
}

int xrp_set_address_map(struct xrp_address_map *map,
			size_t n,
			const struct xrp_address_map_entry *entry)
{
	struct xrp_address_map_entry *p = map->entry;

	if (n > map->n) {
		p = kmalloc_array(n, sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;
	}
	memcpy(p, entry, n * sizeof(*p));
	if (n > map->n) {
		kfree(map->entry);
		map->entry = p;
	}
	map->n = n;
	sort(map->entry, map->n, sizeof(*map->entry),
	     xrp_compare_address_sort, NULL);

	return 0;
}

void xrp_free_address_map(struct xrp_address_map *map)
{
	kfree(map->entry);
}

static int xrp_compare_address_search(const void *a, const void *b)
{
	const phys_addr_t *pa = a;
	return xrp_compare_address(*pa, b);
}

struct xrp_address_map_entry *
xrp_get_address_mapping(const struct xrp_address_map *map, phys_addr_t addr)
{
	struct xrp_address_map_entry *entry =
		bsearch(&addr, map->entry, map->n, sizeof(*map->entry),
			xrp_compare_address_search);
	return entry;
}

u32 xrp_translate_to_dsp(const struct xrp_address_map *map, phys_addr_t addr)
{
	struct xrp_address_map_entry *entry = xrp_get_address_mapping(map, addr);

	if (!entry)
		return XRP_NO_TRANSLATION;
	return entry->dst_addr + addr - entry->src_addr;
}
