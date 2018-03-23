#
# Copyright (c) 2017 Cadence Design Systems Inc.
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

AC_INIT([xrp], [1.0])
AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_MACRO_DIR(autoconf)
AM_INIT_AUTOMAKE([foreign subdir-objects silent-rules])
AC_CONFIG_SRCDIR([configure.ac])
AC_PROG_CC
AM_PROG_AS
AC_PROG_RANLIB
AC_CANONICAL_HOST
AC_CONFIG_FILES([Makefile
		xrp-dsp/Makefile
		xrp-example/Makefile
		xrp-host/Makefile])

AC_ARG_ENABLE(dsp,
	      [AS_HELP_STRING([--enable-dsp],
			      [build DSP XRP library [no]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_dsp=false],
		     [build_dsp=true])],
	      [build_dsp=false])
AM_CONDITIONAL([BUILD_DSP], [test x$build_dsp = xtrue])

AC_ARG_ENABLE(standalone,
	      [AS_HELP_STRING([--enable-standalone],
			      [build standalone library/example [no]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_standalone=false],
		     [build_standalone=true])],
	      [build_standalone=false])
AM_CONDITIONAL([BUILD_STANDALONE], [test x$build_standalone = xtrue])

AC_ARG_ENABLE(hosted,
	      [AS_HELP_STRING([--enable-hosted],
			      [build hosted library/example [yes]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_hosted=false],
		     [build_hosted=true])],
	      [build_hosted=true])
AM_CONDITIONAL([BUILD_HOSTED], [test x$build_hosted = xtrue])

AC_ARG_ENABLE(single,
	      [AS_HELP_STRING([--enable-single],
			      [build single library/example [no]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_single=false],
		     [build_single=true])],
	      [build_single=false])
AM_CONDITIONAL([BUILD_SINGLE], [test x$build_single = xtrue])

AC_ARG_ENABLE(example,
	      [AS_HELP_STRING([--enable-example],
			      [build example application [no]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_example=false],
		     [build_example=true])],
	      [build_example=false])
AM_CONDITIONAL([BUILD_EXAMPLE], [test x$build_example = xtrue])

AC_ARG_ENABLE(threads,
	      [AS_HELP_STRING([--enable-threads],
			      [enable thread support [detect]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [use_threads=false],
		     [use_threads=true])],
	      [])

case "$host_os" in
linux*)
	HOST_OS=linux
	use_threads=${use_threads:-true}
	AS_IF([test "x${use_threads}" = xtrue],
	      [THREADS_IMPL=pthread
	       THREADS_CFLAGS=-pthread
	       THREADS_LDFLAGS=-pthread])
	;;
elf)
	HOST_OS=elf
	AC_CHECK_HEADER([xtensa/xos.h],
			[have_threads=true],
			[have_threads=false])
	use_threads=${use_threads:-${have_threads}}
	AS_IF([test "x${use_threads}" = xtrue],
	      [AS_IF([test "x${have_threads}" != xtrue],
		     [AC_MSG_ERROR([*** threads are not supported])])
	       THREADS_IMPL=xos
	       THREADS_LDFLAGS=-lxos
	       AC_DEFINE(HAVE_THREADS_XOS)])
	;;
esac
AC_SUBST(HOST_OS)
AC_SUBST(THREADS_IMPL,["${THREADS_IMPL:-single}"])
AC_SUBST(THREADS_CFLAGS)
AC_SUBST(THREADS_LDFLAGS)
AM_CONDITIONAL([HOST_OS_LINUX], [test x$HOST_OS = xlinux])

AM_CONDITIONAL([USE_THREADS], [test x$use_threads = xtrue])

AC_ARG_WITH([libfdt],
	    AS_HELP_STRING([--with-libfdt], [Prefix of libfdt headers/library]),
	    [case "${withval}" in
	     (no)
		AC_MSG_ERROR([*** libfdt is a required dependency])
		;;
	     (yes)
		AC_MSG_ERROR([*** --with-libfdt requires you to specify a path])
		;;
	     (*)
		LIBFDT_CPPFLAGS="-I${withval}/include"
		LIBFDT_LDFLAGS="-L${withval}/lib"
		;;
	     esac],[])

AC_SUBST(LIBFDT_CPPFLAGS)
AC_SUBST(LIBFDT_LDFLAGS)

AS_IF([test x$build_dsp = xfalse],
      [
      AC_MSG_CHECKING([for working _Atomic support])
      AC_COMPILE_IFELSE([
			AC_LANG_PROGRAM([[struct { _Atomic int i; _Atomic enum {A, B} e; } s;]],
					[[++s.i; s.e = A;]])
			],
			[
			AC_DEFINE([HAVE_ATOMIC])
			AC_MSG_RESULT([yes])
			],
			[AC_MSG_RESULT([no])])
      ])

AS_IF([test x$build_dsp = xfalse -a x$build_standalone = xtrue],
      [
      AC_CHECK_HEADERS([valgrind/memcheck.h])
      ])

AS_IF([test x$build_dsp = xfalse -a x$build_example = xtrue -a x$build_standalone = xtrue],
      [
      saved_CPPFLAGS="$CPPFLAGS"
      saved_LDFLAGS="$LDFLAGS"
      saved_LIBS="$LIBS"
      CPPFLAGS="$CPPFLAGS $LIBFDT_CPPFLAGS"
      LDFLAGS="$LDFLAGS $LIBFDT_LDFLAGS"
      AC_CHECK_HEADER([libfdt.h],, [AC_MSG_FAILURE([No usable libfdt.h is found])])
      AC_CHECK_LIB([fdt], [fdt_node_offset_by_compatible],,
		   AC_MSG_FAILURE([No usable libfdt is found]))
      AC_CHECK_FUNCS([fdt_getprop fdt_strerror],,
		     AC_MSG_FAILURE([No usable libfdt is found]))
      CPPFLAGS="$saved_CPPFLAGS"
      LDFLAGS="$saved_LDFLAGS"
      LIBS="$saved_LIBS"
      AC_CHECK_PROG(DTC, [dtc], [dtc], [no])
      AS_IF([test x$DTC = xno],
	    [AC_MSG_FAILURE([No usable dtc is found])])
      ])

AC_SUBST(DSP_CORE, ["${DSP_CORE:-visionp6cnn_ao_exls}"])
AC_ARG_VAR(DSP_CORE, [compile DSP code for the specific Xtensa core])

AC_SUBST(DSP_LSP, ["${DSP_LSP:-\$(srcdir)/MW-MP/P6_0/xtensa-elf/lib/sim-stacklocal}"])
AC_ARG_VAR(DSP_LSP, [use specific Xtensa LSP for example firmware])

AC_SUBST(DSP_COMM_BASE, ["${DSP_COMM_BASE:-0xf0000000}"])
AC_ARG_VAR(DSP_COMM_BASE, [DSP communication base address for fast simulation
	   example firmware])

AC_SUBST(DSP_CACHEATTR, ["${DSP_CACHEATTR:-0x44441141}"])
AC_ARG_VAR(DSP_CACHEATTR, [default DSP memmap cacheattr for example firmware])

AC_ARG_VAR(DTC, [Device Tree Compiler to use])

AC_OUTPUT
