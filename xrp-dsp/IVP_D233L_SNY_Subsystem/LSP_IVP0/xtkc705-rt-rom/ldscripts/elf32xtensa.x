/* This linker script generated from xt-genldscripts.tpp for LSP /media/sf_sugawara/svn/trunk/act/2762/workspaces/lin_apk23_ref/XtensaInfo/Models/IVPEP_SNY_for_233L_memmap/xtkc705-rt-rom */
/* Linker Script for default link */
/*  Some problem in the LSP memory map file used to generate this linker script
    prevented generating a working linker script.  However, it is a common issue
    that the user can correct by editing the memory map, so rather than not
    include this standard LSP, the LSP is installed anyway and the linker issues
    an error if any attempt is made to link using this LSP.  This linker error
    is accomplished using the following linker ASSERT statement.  */
_dummy_symbol_ = ASSERT(0,"ERROR: The /media/sf_sugawara/svn/trunk/act/2762/workspaces/lin_apk23_ref/XtensaInfo/Models/IVPEP_SNY_for_233L_memmap/xtkc705-rt-rom LSP is unavailable
ERROR: ROMING option specified in LSP memory map but the reset vector is in a writable memory
ERROR: (iram0) that does not contain the .rom.store section.
ERROR: This would pack the reset vector itself, making it unable to unpack the ROM store.
ERROR: If other sections in iram0 allow, try editing the LSP
ERROR: memory map to remove the writable attribute of that memory.
ERROR: This error normally occurs when a ROM is configured and reset vector is placed in RAM.
ERROR: Edit the LSP's memory map and rerun xt-genldscripts to correct this error.
ERROR: Refer to the Xtensa LSP Reference Manual for more details.");
