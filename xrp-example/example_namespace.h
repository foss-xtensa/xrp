/*
 * Copyright (c) 2017 Cadence Design Systems Inc.
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

#ifndef _EXAMPLE_NAMESPACE_H
#define _EXAMPLE_NAMESPACE_H

#define XRP_EXAMPLE_V1_NSID_INITIALIZER \
	{0x47, 0xf4, 0x5d, 0x8c, 0x99, 0xc5, 0x11, 0xe7, \
	 0xb5, 0x86, 0x00, 0x21, 0xcc, 0x4a, 0x5f, 0xb6}
#define XRP_EXAMPLE_V1_NSID (unsigned char [])XRP_EXAMPLE_V1_NSID_INITIALIZER

#define XRP_EXAMPLE_V2_NSID_INITIALIZER \
	{0x33, 0x56, 0xfc, 0x3c, 0x63, 0x27, 0x40, 0x96, \
	 0x8a, 0x33, 0x1a, 0x5c, 0xca, 0x3b, 0xa1, 0x64}
#define XRP_EXAMPLE_V2_NSID (unsigned char [])XRP_EXAMPLE_V2_NSID_INITIALIZER

#define XRP_EXAMPLE_V3_NSID_INITIALIZER \
	{0x4a, 0x86, 0x5c, 0xd6, 0xcf, 0xef, 0x4c, 0x83, \
	 0xb2, 0x72, 0xb3, 0x51, 0x31, 0x84, 0xd1, 0xc4}
#define XRP_EXAMPLE_V3_NSID (unsigned char [])XRP_EXAMPLE_V3_NSID_INITIALIZER

enum {
	EXAMPLE_V2_CMD_OK,
	EXAMPLE_V2_CMD_FAIL,
	EXAMPLE_V2_CMD_LONG,
	EXAMPLE_V2_CMD_SHORT,
};

struct example_v2_cmd {
	uint32_t cmd;
};

struct example_v2_rsp {
	uint32_t v;
};

struct example_v3_cmd {
	uint32_t off;
	uint32_t sz;
	uint32_t timeout;
};

struct example_v3_rsp {
	uint32_t code;
};

#endif
