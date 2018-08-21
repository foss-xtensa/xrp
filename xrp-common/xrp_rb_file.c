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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "xrp_rb_file.h"

#ifdef HAVE_OPENCOOKIE

static ssize_t rb_write(void *cookie, const char *buf, size_t size)
{
	volatile struct xrp_ring_buffer *rb = cookie;
	uint32_t read = rb->read;
	uint32_t write = rb->write;
	size_t total;
	size_t tail;

	tail = rb->size - write;
	if (read > write) {
		total = read - 1 - write;
		tail = total;
	} else if (read == write) {
		total = rb->size - 1;
	} else {
		total = rb->size - 1 - write + read;
		if (total < tail)
			tail = total;
	}

	if (size < tail)
		tail = size;

	memcpy((char *)rb->data + write, buf, tail);
	buf += tail;
	write += tail;
	if (write == rb->size)
		write = 0;
	size -= tail;
	total -= tail;
	if (size && total) {
		if (size < total)
			total = size;
		memcpy((char *)rb->data, buf, total);
		write += total;
	} else {
		total = 0;
	}
	rb->write = write;
	return tail + total;
}

FILE *xrp_make_rb_file(struct xrp_ring_buffer *rb)
{
	static cookie_io_functions_t rb_ops = {
		.write = rb_write,
	};
	FILE *f = fopencookie(rb, "w", rb_ops);

	if (f)
		setvbuf(f, NULL, _IONBF, 0);

	return f;
}

#else

FILE *xrp_make_rb_file(struct xrp_ring_buffer *rb)
{
	(void *)rb;
	return NULL;
}

#endif
