/*
 * Copyright (c) 2018 Cadence Design Systems Inc.
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

#include <string.h>
#include "xrp_rb_file.h"

static size_t xrp_rb_write_some(void *cookie, const void *buf, size_t size)
{
	volatile struct xrp_ring_buffer *rb = cookie;
	uint32_t read = rb->read;
	uint32_t write = rb->write;
	size_t tail;

	if (read > write) {
		tail = read - 1 - write;
	} else if (read) {
		tail = rb->size - write;
	} else {
		tail = rb->size - 1 - write;
	}

	if (size < tail)
		tail = size;

	memcpy((char *)rb->data + write, buf, tail);

	write += tail;
	if (write == rb->size)
		write = 0;
	rb->write = write;

	return tail;
}

size_t xrp_rb_write(void *cookie, const void *buf, size_t size)
{
	size_t write_total = 0;
	const char *p = buf;

	while (size) {
		size_t write = xrp_rb_write_some(cookie, p, size);

		if (write == 0)
			break;

		p += write;
		size -= write;
		write_total += write;
	}
	return write_total;
}
