// Copyright (c) 2005-2014 by Cadence Design Systems, Inc.  ALL RIGHTS RESERVED.
// These coded instructions, statements, and computer programs are the
// copyrighted works and confidential proprietary information of
// Cadence Design Systems, Inc. They may not be modified, copied, reproduced,
// distributed, or disclosed to third parties in any manner, medium, or form,
// in whole or in part, without the prior written consent of Cadence Design
// Systems, Inc.

// Defines for Host
#ifndef Host_SIM_CLIENT_FILE
#define Host_SIM_CLIENT_FILE
#endif

// Defines for P6_0
#ifndef P6_0_SIM_CLIENT_FILE
#define P6_0_SIM_CLIENT_FILE
#endif

// Defines for P6_1
#ifndef P6_1_SIM_CLIENT_FILE
#define P6_1_SIM_CLIENT_FILE
#endif

// Define the XTSC logger
#ifdef XTSC_LOG
--logging=$(XTSC_SCRIPT_FILE_PATH)/SubSystem.logger.txt
#endif

--no_default_local_mem

--xtensa_core=D_233L_pif128_LC

// Create SystemRAM
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0x60000000
--set_memory_parm=memory_byte_size=536870912
--set_memory_parm=read_delay=1
--set_memory_parm=block_read_delay=1
--set_memory_parm=burst_read_delay=1
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=1
--set_memory_parm=block_write_delay=1
--set_memory_parm=burst_write_delay=1
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=255
--create_memory=SystemRAM

// Create SystemROM
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0x50000000
--set_memory_parm=memory_byte_size=16777216
--set_memory_parm=read_delay=1
--set_memory_parm=block_read_delay=1
--set_memory_parm=burst_read_delay=1
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=1
--set_memory_parm=block_write_delay=1
--set_memory_parm=burst_write_delay=1
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=2
--create_memory=SystemROM

// Create SystemRAM_L
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0x00000000
--set_memory_parm=memory_byte_size=268435456
--set_memory_parm=read_delay=1
--set_memory_parm=block_read_delay=1
--set_memory_parm=burst_read_delay=1
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=1
--set_memory_parm=block_write_delay=1
--set_memory_parm=burst_write_delay=1
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=2
--create_memory=SystemRAM_L

// Create SharedRAM_L
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0xf0000000
--set_memory_parm=memory_byte_size=218103808
--set_memory_parm=read_delay=1
--set_memory_parm=block_read_delay=1
--set_memory_parm=burst_read_delay=1
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=1
--set_memory_parm=block_write_delay=1
--set_memory_parm=burst_write_delay=1
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=2
--create_memory=SharedRAM_L

// Create SystemROM_L
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0xfe000000
--set_memory_parm=memory_byte_size=33554432
--set_memory_parm=read_delay=1
--set_memory_parm=block_read_delay=1
--set_memory_parm=burst_read_delay=1
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=1
--set_memory_parm=block_write_delay=1
--set_memory_parm=burst_write_delay=1
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=2
--create_memory=SystemROM_L

// Instantiate Host's components
#include "$(XTSC_SCRIPT_FILE_PATH)/Host.inc"

// Instantiate P6_0's components
#include "$(XTSC_SCRIPT_FILE_PATH)/P6_0.inc"

// Instantiate P6_1's components
#include "$(XTSC_SCRIPT_FILE_PATH)/P6_1.inc"

// Instantiate inter-processor interconnect

// Create inbound arbiter for Host
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=7
--set_arbiter_parm=arbitration_phase=400
--set_arbiter_parm=master_byte_widths=16
--set_arbiter_parm=slave_byte_width=16
--create_arbiter=Host_inbound_arb

// Connect the inbound arbiter to the inbound router
--connect=Host_inbound_arb,master_port,slave_port,Host_inbound_rte

// Create outbound router for Host
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/Host_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=master_byte_width=16
--set_router_parm=slave_byte_widths=16
--create_router=Host_outbound_rte

// Connect Host's pif to Host's outbound router
--connect=Host,pif,slave_port,Host_outbound_rte

// Create inbound arbiter for P6_0
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=7
--set_arbiter_parm=arbitration_phase=400
--set_arbiter_parm=master_byte_widths=16
--set_arbiter_parm=slave_byte_width=16
--create_arbiter=P6_0_inbound_arb

// Connect the inbound arbiter to the inbound router
--connect=P6_0_inbound_arb,master_port,slave_port,P6_0_inbound_rte

// Create outbound router for P6_0
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/P6_0_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=master_byte_width=16
--set_router_parm=slave_byte_widths=16
--create_router=P6_0_outbound_rte

// Create outbound router for P6_0 idma
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/P6_0_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=master_byte_width=16
--set_router_parm=slave_byte_widths=16
--create_router=P6_0_idma_outbound_rte

// Connect P6_0's pif and idma to P6_0's outbound router
--connect=P6_0,pif,slave_port,P6_0_outbound_rte
--connect=P6_0,idma0,slave_port,P6_0_idma_outbound_rte

// Create inbound arbiter for P6_1
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=7
--set_arbiter_parm=arbitration_phase=400
--set_arbiter_parm=master_byte_widths=16
--set_arbiter_parm=slave_byte_width=16
--create_arbiter=P6_1_inbound_arb

// Connect the inbound arbiter to the inbound router
--connect=P6_1_inbound_arb,master_port,slave_port,P6_1_inbound_rte

// Create outbound router for P6_1
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/P6_1_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=master_byte_width=16
--set_router_parm=slave_byte_widths=16
--create_router=P6_1_outbound_rte

// Create outbound router for P6_1 idma
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/P6_1_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=master_byte_width=16
--set_router_parm=slave_byte_widths=16
--create_router=P6_1_idma_outbound_rte

// Connect P6_1's pif and idma to P6_1's outbound router
--connect=P6_1,pif,slave_port,P6_1_outbound_rte
--connect=P6_1,idma0,slave_port,P6_1_idma_outbound_rte

// Create TestBenchMaster xtsc_master
--set_master_parm=script_file=$(XTSC_SCRIPT_FILE_PATH)/TestBenchMaster.vec
--create_master=TestBenchMaster

// Create router for the xtsc_master
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/TestBenchMaster_rte.tab
--set_router_parm=num_slaves=1
--set_router_parm=default_port_num=0
--create_router=TestBenchMaster_rte

// Connect the TestBenchMaster to the router
--connect=TestBenchMaster,master_port,slave_port,TestBenchMaster_rte

// Bus arbiter masters - P6_0, P6_1, Host, and the TestBenchMaster
--set_arbiter_parm=num_masters=6
--set_arbiter_parm=route_id_lsb=1
--set_arbiter_parm=master_byte_widths=16,16,16,16,16,16
--set_arbiter_parm=slave_byte_width=16
--create_arbiter=BUS_arb

// Create common bus router
// Bus router slaves - P6_0, P6_1, Host
//                     P6_1's MMIO, Host's MMIO, P6_0's MMIO,
//                     SystemRAM, SystemROM, SystemRAM_L, SharedRAM_L, SystemROM_L
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/bus_rte.tab
--set_router_parm=immediate_timing=true
--set_router_parm=num_slaves=8
--set_router_parm=default_port_num=666
--create_router=BUS_rte

// Instantiate the common bus by connecting the BUS router and arbiter
--connect=BUS_arb,master_port,slave_port,BUS_rte

// Connect the common BUS router to all processors
--connect=BUS_rte,master_port[0],slave_port[0],P6_0_inbound_arb
--connect=BUS_rte,master_port[1],slave_port[0],P6_1_inbound_arb
--connect=BUS_rte,master_port[2],slave_port[0],Host_inbound_arb
// Connect SystemRAM, SystemROM to the common bus router
--connect=BUS_rte,master_port[3],slave_port,SystemRAM
--connect=BUS_rte,master_port[4],slave_port,SystemROM
// Connect DeviceMemories to the common bus router
--connect=BUS_rte,master_port[5],slave_port,SystemRAM_L
--connect=BUS_rte,master_port[6],slave_port,SharedRAM_L
--connect=BUS_rte,master_port[7],slave_port,SystemROM_L

// Connect processor's outbound router to BUS arbiter
--connect=P6_0_outbound_rte,master_port[0],slave_port[0],BUS_arb
--connect=P6_0_idma_outbound_rte,master_port[0],slave_port[1],BUS_arb
--connect=P6_1_outbound_rte,master_port[0],slave_port[2],BUS_arb
--connect=P6_1_idma_outbound_rte,master_port[0],slave_port[3],BUS_arb
--connect=Host_outbound_rte,master_port[0],slave_port[4],BUS_arb

// Connect the TestBench xtsc_master router to the last port of the BUS_arb
--connect=TestBenchMaster_rte,master_port[0],slave_port[5],BUS_arb

// Connect the outbound router to other processors (if fast-paths present)
