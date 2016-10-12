/* This linker script generated from xt-genldscripts.tpp for LSP /media/sf_sugawara/svn/trunk/act/2762/workspaces/lin_apk23_ref/XtensaInfo/Models/IVPEP_SNY_for_233L_memmap/sim-local */
/* Linker Script for default link */
MEMORY
{
  dram0_0_seg :                       	org = 0x00010000, len = 0x10000
  dram1_0_seg :                       	org = 0x00030000, len = 0xE000
  iram0_0_seg :                       	org = 0x00040000, len = 0x300
  iram0_2_seg :                       	org = 0x00040400, len = 0x178
  iram0_3_seg :                       	org = 0x00040578, len = 0x8
  iram0_4_seg :                       	org = 0x00040580, len = 0x38
  iram0_5_seg :                       	org = 0x000405B8, len = 0x8
  iram0_6_seg :                       	org = 0x000405C0, len = 0x38
  iram0_7_seg :                       	org = 0x000405F8, len = 0x8
  iram0_8_seg :                       	org = 0x00040600, len = 0x38
  iram0_9_seg :                       	org = 0x00040638, len = 0x8
  iram0_10_seg :                      	org = 0x00040640, len = 0x38
  iram0_11_seg :                      	org = 0x00040678, len = 0x8
  iram0_12_seg :                      	org = 0x00040680, len = 0x38
  iram0_13_seg :                      	org = 0x000406B8, len = 0x48
  iram0_14_seg :                      	org = 0x00040700, len = 0x40
  iram0_15_seg :                      	org = 0x00040740, len = 0x18C0
  srom0_seg :                         	org = 0x50000000, len = 0x100000
  sram0_seg :                         	org = 0x60000000, len = 0x20000000
  shared_sram_0_seg :                 	org = 0xF0000000, len = 0x1000000
}

PHDRS
{
  dram0_0_phdr PT_LOAD;
  dram0_0_bss_phdr PT_LOAD;
  dram1_0_phdr PT_LOAD;
  dram1_0_bss_phdr PT_LOAD;
  dram1_stack_phdr PT_LOAD;
  iram0_0_phdr PT_LOAD;
  iram0_1_phdr PT_LOAD;
  iram0_2_phdr PT_LOAD;
  iram0_3_phdr PT_LOAD;
  iram0_4_phdr PT_LOAD;
  iram0_5_phdr PT_LOAD;
  iram0_6_phdr PT_LOAD;
  iram0_7_phdr PT_LOAD;
  iram0_8_phdr PT_LOAD;
  iram0_9_phdr PT_LOAD;
  iram0_10_phdr PT_LOAD;
  iram0_11_phdr PT_LOAD;
  iram0_12_phdr PT_LOAD;
  iram0_13_phdr PT_LOAD;
  iram0_14_phdr PT_LOAD;
  iram0_15_phdr PT_LOAD;
  srom0_phdr PT_LOAD;
  sram0_phdr PT_LOAD;
  sram0_bss_phdr PT_LOAD;
  shared_sram_0_phdr PT_LOAD;
  shared_sram_0_bss_phdr PT_LOAD;
}


/*  Default entry point:  */
ENTRY(_ResetVector)

/*  Memory boundary addresses:  */
_memmap_mem_dram0_start = 0x10000;
_memmap_mem_dram0_end   = 0x20000;
_memmap_mem_dram1_start = 0x30000;
_memmap_mem_dram1_end   = 0x40000;
_memmap_mem_iram0_start = 0x40000;
_memmap_mem_iram0_end   = 0x42000;
_memmap_mem_srom_start = 0x50000000;
_memmap_mem_srom_end   = 0x50100000;
_memmap_mem_sram_start = 0x60000000;
_memmap_mem_sram_end   = 0x80000000;
_memmap_mem_shared_sram_start = 0xf0000000;
_memmap_mem_shared_sram_end   = 0xf1000000;
_memmap_mem_MMIO_start = 0xf1000000;
_memmap_mem_MMIO_end   = 0xf2000000;
MMIO = 0xf1000000;

/*  Memory segment boundary addresses:  */
_memmap_seg_dram0_0_start = 0x10000;
_memmap_seg_dram0_0_max   = 0x20000;
_memmap_seg_dram1_0_start = 0x30000;
_memmap_seg_dram1_0_max   = 0x3e000;
_memmap_seg_iram0_0_start = 0x40000;
_memmap_seg_iram0_0_max   = 0x40300;
_memmap_seg_iram0_2_start = 0x40400;
_memmap_seg_iram0_2_max   = 0x40578;
_memmap_seg_iram0_3_start = 0x40578;
_memmap_seg_iram0_3_max   = 0x40580;
_memmap_seg_iram0_4_start = 0x40580;
_memmap_seg_iram0_4_max   = 0x405b8;
_memmap_seg_iram0_5_start = 0x405b8;
_memmap_seg_iram0_5_max   = 0x405c0;
_memmap_seg_iram0_6_start = 0x405c0;
_memmap_seg_iram0_6_max   = 0x405f8;
_memmap_seg_iram0_7_start = 0x405f8;
_memmap_seg_iram0_7_max   = 0x40600;
_memmap_seg_iram0_8_start = 0x40600;
_memmap_seg_iram0_8_max   = 0x40638;
_memmap_seg_iram0_9_start = 0x40638;
_memmap_seg_iram0_9_max   = 0x40640;
_memmap_seg_iram0_10_start = 0x40640;
_memmap_seg_iram0_10_max   = 0x40678;
_memmap_seg_iram0_11_start = 0x40678;
_memmap_seg_iram0_11_max   = 0x40680;
_memmap_seg_iram0_12_start = 0x40680;
_memmap_seg_iram0_12_max   = 0x406b8;
_memmap_seg_iram0_13_start = 0x406b8;
_memmap_seg_iram0_13_max   = 0x40700;
_memmap_seg_iram0_14_start = 0x40700;
_memmap_seg_iram0_14_max   = 0x40740;
_memmap_seg_iram0_15_start = 0x40740;
_memmap_seg_iram0_15_max   = 0x42000;
_memmap_seg_srom0_start = 0x50000000;
_memmap_seg_srom0_max   = 0x50100000;
_memmap_seg_sram0_start = 0x60000000;
_memmap_seg_sram0_max   = 0x80000000;
_memmap_seg_shared_sram_0_start = 0xf0000000;
_memmap_seg_shared_sram_0_max   = 0xf1000000;

_rom_store_table = 0;
PROVIDE(_memmap_vecbase_reset = 0x40400);
PROVIDE(_memmap_reset_vector = 0x40000);
/* Various memory-map dependent cache attribute settings: */
_memmap_cacheattr_wb_base = 0x20001101;
_memmap_cacheattr_wt_base = 0x20001101;
_memmap_cacheattr_bp_base = 0x20002202;
_memmap_cacheattr_unused_mask = 0x0FFF00F0;
_memmap_cacheattr_wb_trapnull = 0x22221121;
_memmap_cacheattr_wba_trapnull = 0x22221121;
_memmap_cacheattr_wbna_trapnull = 0x22221121;
_memmap_cacheattr_wt_trapnull = 0x22221121;
_memmap_cacheattr_bp_trapnull = 0x22222222;
_memmap_cacheattr_wb_strict = 0x2FFF11F1;
_memmap_cacheattr_wt_strict = 0x2FFF11F1;
_memmap_cacheattr_bp_strict = 0x2FFF22F2;
_memmap_cacheattr_wb_allvalid = 0x22221121;
_memmap_cacheattr_wt_allvalid = 0x22221121;
_memmap_cacheattr_bp_allvalid = 0x22222222;
PROVIDE(_memmap_cacheattr_reset = _memmap_cacheattr_wb_trapnull);

SECTIONS
{

  .dram0.rodata : ALIGN(4)
  {
    _dram0_rodata_start = ABSOLUTE(.);
    *(.dram0.rodata)
    _dram0_rodata_end = ABSOLUTE(.);
  } >dram0_0_seg :dram0_0_phdr

  .rodata : ALIGN(4)
  {
    _rodata_start = ABSOLUTE(.);
    *(.rodata)
    *(.rodata.*)
    *(.gnu.linkonce.r.*)
    *(.rodata1)
    __XT_EXCEPTION_TABLE__ = ABSOLUTE(.);
    KEEP (*(.xt_except_table))
    KEEP (*(.gcc_except_table))
    *(.gnu.linkonce.e.*)
    *(.gnu.version_r)
    KEEP (*(.eh_frame))
    /*  C++ constructor and destructor tables, properly ordered:  */
    KEEP (*crtbegin.o(.ctors))
    KEEP (*(EXCLUDE_FILE (*crtend.o) .ctors))
    KEEP (*(SORT(.ctors.*)))
    KEEP (*(.ctors))
    KEEP (*crtbegin.o(.dtors))
    KEEP (*(EXCLUDE_FILE (*crtend.o) .dtors))
    KEEP (*(SORT(.dtors.*)))
    KEEP (*(.dtors))
    /*  C++ exception handlers table:  */
    __XT_EXCEPTION_DESCS__ = ABSOLUTE(.);
    *(.xt_except_desc)
    *(.gnu.linkonce.h.*)
    __XT_EXCEPTION_DESCS_END__ = ABSOLUTE(.);
    *(.xt_except_desc_end)
    *(.dynamic)
    *(.gnu.version_d)
    . = ALIGN(4);		/* this table MUST be 4-byte aligned */
    _bss_table_start = ABSOLUTE(.);
    LONG(_bss_start)
    LONG(_bss_end)
    LONG(_dram1_bss_start)
    LONG(_dram1_bss_end)
    LONG(_sram_bss_start)
    LONG(_sram_bss_end)
    LONG(_shared_sram_bss_start)
    LONG(_shared_sram_bss_end)
    _bss_table_end = ABSOLUTE(.);
    _rodata_end = ABSOLUTE(.);
  } >dram0_0_seg :dram0_0_phdr

  .dram0.literal : ALIGN(4)
  {
    _dram0_literal_start = ABSOLUTE(.);
    *(.dram0.literal)
    _dram0_literal_end = ABSOLUTE(.);
  } >dram0_0_seg :dram0_0_phdr

  .dram0.data : ALIGN(4)
  {
    _dram0_data_start = ABSOLUTE(.);
    *(.dram0.data)
    _dram0_data_end = ABSOLUTE(.);
  } >dram0_0_seg :dram0_0_phdr

  .data : ALIGN(4)
  {
    _data_start = ABSOLUTE(.);
    *(.data)
    *(.data.*)
    *(.gnu.linkonce.d.*)
    KEEP(*(.gnu.linkonce.d.*personality*))
    *(.data1)
    *(.sdata)
    *(.sdata.*)
    *(.gnu.linkonce.s.*)
    *(.sdata2)
    *(.sdata2.*)
    *(.gnu.linkonce.s2.*)
    KEEP(*(.jcr))
    _data_end = ABSOLUTE(.);
  } >dram0_0_seg :dram0_0_phdr

  .bss (NOLOAD) : ALIGN(8)
  {
    . = ALIGN (8);
    _bss_start = ABSOLUTE(.);
    *(.dynsbss)
    *(.sbss)
    *(.sbss.*)
    *(.gnu.linkonce.sb.*)
    *(.scommon)
    *(.sbss2)
    *(.sbss2.*)
    *(.gnu.linkonce.sb2.*)
    *(.dynbss)
    *(.bss)
    *(.bss.*)
    *(.gnu.linkonce.b.*)
    *(COMMON)
    *(.dram0.bss)
    . = ALIGN (8);
    _bss_end = ABSOLUTE(.);
    _end = ALIGN(0x8);
    PROVIDE(end = ALIGN(0x8));
    _stack_sentry = ALIGN(0x8);
    _memmap_seg_dram0_0_end = ALIGN(0x8);
  } >dram0_0_seg :dram0_0_bss_phdr
  __stack = 0x20000;
  _heap_sentry = 0x20000;

  .dram1.rodata : ALIGN(4)
  {
    _dram1_rodata_start = ABSOLUTE(.);
    *(.dram1.rodata)
    _dram1_rodata_end = ABSOLUTE(.);
  } >dram1_0_seg :dram1_0_phdr

  .dram1.literal : ALIGN(4)
  {
    _dram1_literal_start = ABSOLUTE(.);
    *(.dram1.literal)
    _dram1_literal_end = ABSOLUTE(.);
  } >dram1_0_seg :dram1_0_phdr

  .ResetVector.literal : ALIGN(4)
  {
    _ResetVector_literal_start = ABSOLUTE(.);
    *(.ResetVector.literal)
    _ResetVector_literal_end = ABSOLUTE(.);
  } >dram1_0_seg :dram1_0_phdr

  .dram1.data : ALIGN(4)
  {
    _dram1_data_start = ABSOLUTE(.);
    *(.dram1.data)
    _dram1_data_end = ABSOLUTE(.);
  } >dram1_0_seg :dram1_0_phdr

  .dram1.bss (NOLOAD) : ALIGN(8)
  {
    . = ALIGN (8);
    _dram1_bss_start = ABSOLUTE(.);
    *(.dram1.bss)
    . = ALIGN (8);
    _dram1_bss_end = ABSOLUTE(.);
    _memmap_seg_dram1_0_end = ALIGN(0x8);
  } >dram1_0_seg :dram1_0_bss_phdr

  .ResetVector.text : ALIGN(4)
  {
    _ResetVector_text_start = ABSOLUTE(.);
    KEEP (*(.ResetVector.text))
    _ResetVector_text_end = ABSOLUTE(.);
    _memmap_seg_iram0_0_end = ALIGN(0x8);
  } >iram0_0_seg :iram0_0_phdr

  .WindowVectors.text : ALIGN(4)
  {
    _WindowVectors_text_start = ABSOLUTE(.);
    KEEP (*(.WindowVectors.text))
    _WindowVectors_text_end = ABSOLUTE(.);
    _memmap_seg_iram0_2_end = ALIGN(0x8);
  } >iram0_2_seg :iram0_2_phdr

  .Level2InterruptVector.literal : ALIGN(4)
  {
    _Level2InterruptVector_literal_start = ABSOLUTE(.);
    *(.Level2InterruptVector.literal)
    _Level2InterruptVector_literal_end = ABSOLUTE(.);
    _memmap_seg_iram0_3_end = ALIGN(0x8);
  } >iram0_3_seg :iram0_3_phdr

  .Level2InterruptVector.text : ALIGN(4)
  {
    _Level2InterruptVector_text_start = ABSOLUTE(.);
    KEEP (*(.Level2InterruptVector.text))
    _Level2InterruptVector_text_end = ABSOLUTE(.);
    _memmap_seg_iram0_4_end = ALIGN(0x8);
  } >iram0_4_seg :iram0_4_phdr

  .DebugExceptionVector.literal : ALIGN(4)
  {
    _DebugExceptionVector_literal_start = ABSOLUTE(.);
    *(.DebugExceptionVector.literal)
    _DebugExceptionVector_literal_end = ABSOLUTE(.);
    _memmap_seg_iram0_5_end = ALIGN(0x8);
  } >iram0_5_seg :iram0_5_phdr

  .DebugExceptionVector.text : ALIGN(4)
  {
    _DebugExceptionVector_text_start = ABSOLUTE(.);
    KEEP (*(.DebugExceptionVector.text))
    _DebugExceptionVector_text_end = ABSOLUTE(.);
    _memmap_seg_iram0_6_end = ALIGN(0x8);
  } >iram0_6_seg :iram0_6_phdr

  .NMIExceptionVector.literal : ALIGN(4)
  {
    _NMIExceptionVector_literal_start = ABSOLUTE(.);
    *(.NMIExceptionVector.literal)
    _NMIExceptionVector_literal_end = ABSOLUTE(.);
    _memmap_seg_iram0_7_end = ALIGN(0x8);
  } >iram0_7_seg :iram0_7_phdr

  .NMIExceptionVector.text : ALIGN(4)
  {
    _NMIExceptionVector_text_start = ABSOLUTE(.);
    KEEP (*(.NMIExceptionVector.text))
    _NMIExceptionVector_text_end = ABSOLUTE(.);
    _memmap_seg_iram0_8_end = ALIGN(0x8);
  } >iram0_8_seg :iram0_8_phdr

  .KernelExceptionVector.literal : ALIGN(4)
  {
    _KernelExceptionVector_literal_start = ABSOLUTE(.);
    *(.KernelExceptionVector.literal)
    _KernelExceptionVector_literal_end = ABSOLUTE(.);
    _memmap_seg_iram0_9_end = ALIGN(0x8);
  } >iram0_9_seg :iram0_9_phdr

  .KernelExceptionVector.text : ALIGN(4)
  {
    _KernelExceptionVector_text_start = ABSOLUTE(.);
    KEEP (*(.KernelExceptionVector.text))
    _KernelExceptionVector_text_end = ABSOLUTE(.);
    _memmap_seg_iram0_10_end = ALIGN(0x8);
  } >iram0_10_seg :iram0_10_phdr

  .UserExceptionVector.literal : ALIGN(4)
  {
    _UserExceptionVector_literal_start = ABSOLUTE(.);
    *(.UserExceptionVector.literal)
    _UserExceptionVector_literal_end = ABSOLUTE(.);
    _memmap_seg_iram0_11_end = ALIGN(0x8);
  } >iram0_11_seg :iram0_11_phdr

  .UserExceptionVector.text : ALIGN(4)
  {
    _UserExceptionVector_text_start = ABSOLUTE(.);
    KEEP (*(.UserExceptionVector.text))
    _UserExceptionVector_text_end = ABSOLUTE(.);
    _memmap_seg_iram0_12_end = ALIGN(0x8);
  } >iram0_12_seg :iram0_12_phdr

  .DoubleExceptionVector.literal : ALIGN(4)
  {
    _DoubleExceptionVector_literal_start = ABSOLUTE(.);
    *(.DoubleExceptionVector.literal)
    _DoubleExceptionVector_literal_end = ABSOLUTE(.);
    _memmap_seg_iram0_13_end = ALIGN(0x8);
  } >iram0_13_seg :iram0_13_phdr

  .DoubleExceptionVector.text : ALIGN(4)
  {
    _DoubleExceptionVector_text_start = ABSOLUTE(.);
    KEEP (*(.DoubleExceptionVector.text))
    _DoubleExceptionVector_text_end = ABSOLUTE(.);
    _memmap_seg_iram0_14_end = ALIGN(0x8);
  } >iram0_14_seg :iram0_14_phdr

  .iram0.text : ALIGN(4)
  {
    _iram0_text_start = ABSOLUTE(.);
    *(.iram0.literal .iram.literal .iram.text.literal .iram0.text .iram.text)
    _iram0_text_end = ABSOLUTE(.);
  } >iram0_15_seg :iram0_15_phdr

  .text : ALIGN(4)
  {
    _stext = .;
    _text_start = ABSOLUTE(.);
    *(.entry.text)
    *(.init.literal)
    KEEP(*(.init))
    *(.literal .text .literal.* .text.* .stub .gnu.warning .gnu.linkonce.literal.* .gnu.linkonce.t.*.literal .gnu.linkonce.t.*)
    *(.fini.literal)
    KEEP(*(.fini))
    *(.gnu.version)
    _text_end = ABSOLUTE(.);
    _etext = .;
  } >iram0_15_seg :iram0_15_phdr

  .srom.rodata : ALIGN(4)
  {
    _srom_rodata_start = ABSOLUTE(.);
    *(.srom.rodata)
    _srom_rodata_end = ABSOLUTE(.);
  } >srom0_seg :srom0_phdr

  .srom.text : ALIGN(4)
  {
    _srom_text_start = ABSOLUTE(.);
    *(.srom.literal .srom.text)
    _srom_text_end = ABSOLUTE(.);
    _memmap_seg_srom0_end = ALIGN(0x8);
  } >srom0_seg :srom0_phdr

  .sram.rodata : ALIGN(4)
  {
    _sram_rodata_start = ABSOLUTE(.);
    *(.sram.rodata)
    _sram_rodata_end = ABSOLUTE(.);
  } >sram0_seg :sram0_phdr

  .sram.text : ALIGN(4)
  {
    _sram_text_start = ABSOLUTE(.);
    *(.sram.literal .sram.text)
    _sram_text_end = ABSOLUTE(.);
  } >sram0_seg :sram0_phdr

  .sram.data : ALIGN(4)
  {
    _sram_data_start = ABSOLUTE(.);
    *(.sram.data)
    _sram_data_end = ABSOLUTE(.);
  } >sram0_seg :sram0_phdr

  .sram.bss (NOLOAD) : ALIGN(8)
  {
    . = ALIGN (8);
    _sram_bss_start = ABSOLUTE(.);
    *(.sram.bss)
    . = ALIGN (8);
    _sram_bss_end = ABSOLUTE(.);
    _memmap_seg_sram0_end = ALIGN(0x8);
  } >sram0_seg :sram0_bss_phdr

  .shared_sram_0.data : ALIGN(4)
  {
    _shared_sram_0_data_start = ABSOLUTE(.);
    KEEP (*(.shared_sram_0.data))
    _shared_sram_0_data_end = ABSOLUTE(.);
  } >shared_sram_0_seg :shared_sram_0_phdr

  .shared_sram_1.data : ALIGN(4)
  {
    _shared_sram_1_data_start = ABSOLUTE(.);
    KEEP (*(.shared_sram_1.data))
    _shared_sram_1_data_end = ABSOLUTE(.);
  } >shared_sram_0_seg :shared_sram_0_phdr

  .shared_sram.data : ALIGN(4)
  {
    _shared_sram_data_start = ABSOLUTE(.);
    KEEP (*(.shared_sram.data))
    _shared_sram_data_end = ABSOLUTE(.);
  } >shared_sram_0_seg :shared_sram_0_phdr

  .shared_sram.bss (NOLOAD) : ALIGN(8)
  {
    . = ALIGN (8);
    _shared_sram_bss_start = ABSOLUTE(.);
    KEEP (*(.shared_sram.bss))
    . = ALIGN (8);
    _shared_sram_bss_end = ABSOLUTE(.);
    _memmap_seg_shared_sram_0_end = ALIGN(0x8);
  } >shared_sram_0_seg :shared_sram_0_bss_phdr
  .debug  0 :  { *(.debug) }
  .line  0 :  { *(.line) }
  .debug_srcinfo  0 :  { *(.debug_srcinfo) }
  .debug_sfnames  0 :  { *(.debug_sfnames) }
  .debug_aranges  0 :  { *(.debug_aranges) }
  .debug_pubnames  0 :  { *(.debug_pubnames) }
  .debug_info  0 :  { *(.debug_info) }
  .debug_abbrev  0 :  { *(.debug_abbrev) }
  .debug_line  0 :  { *(.debug_line) }
  .debug_frame  0 :  { *(.debug_frame) }
  .debug_str  0 :  { *(.debug_str) }
  .debug_loc  0 :  { *(.debug_loc) }
  .debug_macinfo  0 :  { *(.debug_macinfo) }
  .debug_weaknames  0 :  { *(.debug_weaknames) }
  .debug_funcnames  0 :  { *(.debug_funcnames) }
  .debug_typenames  0 :  { *(.debug_typenames) }
  .debug_varnames  0 :  { *(.debug_varnames) }
  .xt.insn 0 :
  {
    KEEP (*(.xt.insn))
    KEEP (*(.gnu.linkonce.x.*))
  }
  .xt.prop 0 :
  {
    KEEP (*(.xt.prop))
    KEEP (*(.xt.prop.*))
    KEEP (*(.gnu.linkonce.prop.*))
  }
  .xt.lit 0 :
  {
    KEEP (*(.xt.lit))
    KEEP (*(.xt.lit.*))
    KEEP (*(.gnu.linkonce.p.*))
  }
  .debug.xt.callgraph 0 :
  {
    KEEP (*(.debug.xt.callgraph .debug.xt.callgraph.* .gnu.linkonce.xt.callgraph.*))
  }
}

