#
# Copyright (c) 2017 - 2018 Cadence Design Systems Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir) -I$(srcdir)/thread-pthread
AM_CFLAGS = -W -Wall

include_HEADERS = ../xrp_api.h
lib_LIBRARIES =

if BUILD_SIM
lib_LIBRARIES += libxrp-linux-sim.a
endif
if BUILD_NAT
lib_LIBRARIES += libxrp-linux-native.a
endif

libxrp_linux_native_a_CPPFLAGS = $(AM_CPPFLAGS) \
				 -I$(srcdir)/native \
				 -I$(srcdir)/../xrp-kernel
libxrp_linux_native_a_CFLAGS = $(AM_CFLAGS) \
			       -pthread
libxrp_linux_native_a_SOURCES = xrp_host_common.c \
				xrp_threaded_queue.c \
				native/xrp_linux_native.c

libxrp_linux_sim_a_CPPFLAGS = $(AM_CPPFLAGS) \
			      -I$(srcdir)/sim \
			      -I$(srcdir)/../xrp-kernel
libxrp_linux_sim_a_CFLAGS = $(AM_CFLAGS) \
			    -pthread
libxrp_linux_sim_a_SOURCES = xrp_host_common.c \
			     xrp_threaded_queue.c \
			     sim/xrp_linux_sim.c \
			     sim/xrp_alloc.c
