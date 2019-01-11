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

AC_INIT([xrp], [20181022])
AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_MACRO_DIR(autoconf)
AM_INIT_AUTOMAKE([foreign subdir-objects silent-rules])
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([configure.ac])
AC_PROG_CC
AM_PROG_AS
AM_PROG_AR
AC_PROG_RANLIB
AC_CANONICAL_HOST
AC_CONFIG_FILES([Makefile
		 doc/Makefile
		 doc/xrp.conf
		 xrp-common/Makefile
		 xrp-dsp/Makefile
		 xrp-example/Makefile
		 xrp-host/Makefile])

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
AM_CONDITIONAL([HOST_OS_ELF], [test x$HOST_OS = xelf])

AM_CONDITIONAL([USE_THREADS], [test x$use_threads = xtrue])

AC_ARG_ENABLE(host,
	      [AS_HELP_STRING([--enable-host],
			      [build host XRP library [yes]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_host=false],
		     [build_host=true])],
	      [build_host=true])
AM_CONDITIONAL([BUILD_HOST], [test x$build_host = xtrue])

AC_ARG_ENABLE(dsp,
	      [AS_HELP_STRING([--enable-dsp],
			      [build DSP XRP library [detect]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_dsp=false],
		     [build_dsp=true])],
	      [case "$host_cpu" in
	       xtensa*)
			build_dsp=true
			;;
	       *)
			build_dsp=false
			;;
	       esac])
AM_CONDITIONAL([BUILD_DSP], [test x$build_dsp = xtrue])

AC_ARG_ENABLE(standalone,
	      [AS_HELP_STRING([--enable-standalone],
			      [build standalone library/example [yes]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_standalone=false],
		     [build_standalone=true])],
	      [build_standalone=true])
AM_CONDITIONAL([BUILD_STANDALONE], [test x$build_standalone = xtrue])

AC_ARG_ENABLE(hosted,
	      [AS_HELP_STRING([--enable-hosted],
			      [build hosted library/example [detect]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_hosted=false],
		     [build_hosted=true])],
	      [AS_IF([test "x${HOST_OS}" = xlinux],
		     [build_hosted=true],
		     [build_hosted=false])])
AM_CONDITIONAL([BUILD_HOSTED], [test x$build_hosted = xtrue])

AC_ARG_ENABLE(single,
	      [AS_HELP_STRING([--enable-single],
			      [build single library/example [yes]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_single=false],
		     [build_single=true])],
	      [build_single=true])
AM_CONDITIONAL([BUILD_SINGLE], [test x$build_single = xtrue])

AC_ARG_ENABLE(example,
	      [AS_HELP_STRING([--enable-example],
			      [build example application [no]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_example=false],
		     [build_example=true])],
	      [build_example=false])
AM_CONDITIONAL([BUILD_EXAMPLE], [test x$build_example = xtrue])

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

AS_IF([test x$build_host = xtrue],
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

AS_IF([test x$build_host = xtrue -a x$build_standalone = xtrue],
      [
      AC_CHECK_HEADERS([valgrind/memcheck.h])
      ])

AS_IF([test x$build_host = xtrue -a x$build_standalone = xtrue -a x$build_example = xtrue],
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

HW_PORT=simple
AC_ARG_ENABLE(port,
	      [AS_HELP_STRING([--enable-port[[=ARG]]],
			      [enable port ARG [simple]])],
	      [HW_PORT="${enableval}"],
	      [])
AC_SUBST(HW_PORT)

case "${HW_PORT}" in
	hikey960)
		CC=${CC:-xt-xcc --xtensa-core=hifi3_hikey960}
		DSP_LSP=${DSP_LSP:-\$(srcdir)/hikey960}
		DSP_CACHEATTR=${DSP_CACHEATTR:-0x24222222}
		;;
esac

AS_IF([test x$build_dsp = xtrue],
      [
      # xtos_set_interrupt_handler is not available in all XTOS versions,
      # but is preferred to _xtos_set_interrupt_handler when it's present.
      #
      AC_CHECK_FUNC([xtos_set_interrupt_handler])
      ])

AC_CONFIG_FILES([xrp-dsp/simple/Makefile])
AC_CONFIG_FILES([xrp-dsp/hikey960/Makefile])

AC_SUBST(DSP_LSP, ["${DSP_LSP:-\$(srcdir)/MW-MP/P6_0/xtensa-elf/lib/sim-stacklocal}"])
AC_ARG_VAR(DSP_LSP, [use specific Xtensa LSP for example firmware])

AC_SUBST(DSP_COMM_BASE, ["${DSP_COMM_BASE:-0xf0000000}"])
AC_ARG_VAR(DSP_COMM_BASE, [DSP communication base address for standalone
	   example firmware])

AC_SUBST(DSP_CACHEATTR, ["${DSP_CACHEATTR:-0x44441141}"])
AC_ARG_VAR(DSP_CACHEATTR, [default DSP memmap cacheattr for example firmware])

AC_SUBST(HOST_LSP, ["${DSP_LSP:-\$(srcdir)/MW-MP/P6_1/xtensa-elf/lib/sim-stacklocal}"])
AC_ARG_VAR(HOST_LSP, [use specific Xtensa LSP for example standalone ELF host])

AC_SUBST(HOST_CACHEATTR, ["${HOST_CACHEATTR:-0x22222222}"])
AC_ARG_VAR(HOST_CACHEATTR, [default standalone ELF host memmap cacheattr])

AC_ARG_VAR(DTC, [Device Tree Compiler to use])

AC_MSG_NOTICE([

  Building host code:            ${build_host}
  Building DSP code:             ${build_dsp}
  Building hosted code:          ${build_hosted}
  Building standalone code:      ${build_standalone}
  Building single image code:    ${build_single}
  Using threads:                 ${use_threads}
])

AC_OUTPUT
