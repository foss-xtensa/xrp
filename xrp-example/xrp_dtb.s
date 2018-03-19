	.section .rodata
	.globl dt_blob_start
        .type dt_blob_start, @object
	.align 16
dt_blob_start:
	.incbin "xrp.dtb"
        .size dt_blob_start, . - dt_blob_start
