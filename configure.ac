AC_INIT([xrp], [1.0])
AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_MACRO_DIR(autoconf)
AM_INIT_AUTOMAKE([foreign subdir-objects silent-rules])
AC_CONFIG_SRCDIR([configure.ac])
AC_PROG_CC
AM_PROG_AS
AC_PROG_RANLIB
AC_CONFIG_FILES([Makefile
		xrp-dsp/Makefile
		xrp-example/Makefile
		xrp-linux-native/Makefile
		xrp-linux-sim/Makefile])

AC_ARG_ENABLE(dsp,
	      [AS_HELP_STRING([--enable-dsp],
			      [build DSP XRP library [no]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_dsp=false],
		     [build_dsp=true])],
	      [build_dsp=false])
AM_CONDITIONAL([BUILD_DSP], [test x$build_dsp = xtrue])

AC_ARG_ENABLE(sim,
	      [AS_HELP_STRING([--enable-sim],
			      [build fast simulation library/example [no]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_sim=false],
		     [build_sim=true])],
	      [build_sim=false])
AM_CONDITIONAL([BUILD_SIM], [test x$build_sim = xtrue])

AC_ARG_ENABLE(native,
	      [AS_HELP_STRING([--enable-native],
			      [build native library/example [yes]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_native=false],
		     [build_native=true])],
	      [build_native=true])
AM_CONDITIONAL([BUILD_NAT], [test x$build_native = xtrue])

AC_ARG_ENABLE(example,
	      [AS_HELP_STRING([--enable-example],
			      [build example application [no]])],
	      [AS_IF([test "x${enableval}" = xno],
		     [build_example=false],
		     [build_example=true])],
	      [build_example=no])
AM_CONDITIONAL([BUILD_EXAMPLE], [test x$build_example = xtrue])

AS_IF([test x$build_dsp = xfalse -a x$build_sim = xtrue],
      [
      AC_CHECK_HEADERS([valgrind/memcheck.h])
      ])

AS_IF([test x$build_dsp = xfalse -a x$build_example = xtrue -a x$build_sim = xtrue],
      [
      AC_CHECK_HEADER([libfdt.h],, [AC_MSG_FAILURE([No usable libfdt.h is found])])
      saved_LIBS="$LIBS"
      AC_CHECK_LIB([fdt], [fdt_node_offset_by_compatible],,
		   AC_MSG_FAILURE([No usable libfdt is found]))
      AC_CHECK_FUNCS([fdt_getprop fdt_strerror],,
		     AC_MSG_FAILURE([No usable libfdt is found]))
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

AC_ARG_VAR(DTC, [Device Tree Compiler to use])

AC_OUTPUT
