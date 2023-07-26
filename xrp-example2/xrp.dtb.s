/*
 * Copyright (c) 2019 by Cadence Design Systems, Inc. ALL RIGHTS RESERVED. 
 * These coded instructions, statements, and computer programs are the
 * copyrighted works and confidential proprietary information of 
 * Cadence Design Systems Inc. Any rights to use, modify, and create 
 * derivative works of this file are set forth under the terms of your 
 * license agreement with Cadence Design Systems, Inc.
 */

  .section .rodata
  .globl dt_blob_start
        .type dt_blob_start, @object
  .align 16
dt_blob_start:
  .incbin "xrp.dtb"
        .size dt_blob_start, . - dt_blob_start

