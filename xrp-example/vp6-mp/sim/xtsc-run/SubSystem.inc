// Copyright (c) 2005-2014 by Cadence Design Systems, Inc.  ALL RIGHTS RESERVED.
// These coded instructions, statements, and computer programs are the
// copyrighted works and confidential proprietary information of
// Cadence Design Systems, Inc. They may not be modified, copied, reproduced,
// distributed, or disclosed to third parties in any manner, medium, or form,
// in whole or in part, without the prior written consent of Cadence Design
// Systems, Inc.

// Defines for latencies for SystemRAM
#ifndef SYSTEMRAM_DELAY
#define SYSTEMRAM_DELAY 1
#endif

#ifndef SYSTEMRAM_REQUEST_FIFO_DEPTH
#define SYSTEMRAM_REQUEST_FIFO_DEPTH 255
#endif

// Defines for latencies for SystemROM
#ifndef SYSTEMROM_DELAY
#define SYSTEMROM_DELAY 1
#endif

#ifndef SYSTEMROM_REQUEST_FIFO_DEPTH
#define SYSTEMROM_REQUEST_FIFO_DEPTH 2
#endif

// Defines for latencies for Shared_RAM_L
#ifndef SHARED_RAM_L_DELAY
#define SHARED_RAM_L_DELAY 1
#endif

#ifndef SHARED_RAM_L_REQUEST_FIFO_DEPTH
#define SHARED_RAM_L_REQUEST_FIFO_DEPTH 255
#endif

// Defines for DSP_0
#ifndef DSP_0_CONFIG
#define DSP_0_CONFIG visionp6_ao
#endif

#ifndef DSP_0_XTENSA_PARAMS
#define DSP_0_XTENSA_PARAMS
#endif

#ifndef DSP_0_SIM_CLIENT_FILE
#define DSP_0_SIM_CLIENT_FILE
#endif

// Defines for DSP_1
#ifndef DSP_1_CONFIG
#define DSP_1_CONFIG visionp6_ao
#endif

#ifndef DSP_1_XTENSA_PARAMS
#define DSP_1_XTENSA_PARAMS
#endif

#ifndef DSP_1_SIM_CLIENT_FILE
#define DSP_1_SIM_CLIENT_FILE
#endif

// Defines for DSP_2
#ifndef DSP_2_CONFIG
#define DSP_2_CONFIG visionp6_ao
#endif

#ifndef DSP_2_XTENSA_PARAMS
#define DSP_2_XTENSA_PARAMS
#endif

#ifndef DSP_2_SIM_CLIENT_FILE
#define DSP_2_SIM_CLIENT_FILE
#endif

// Defines for DSP_3
#ifndef DSP_3_CONFIG
#define DSP_3_CONFIG visionp6_ao
#endif

#ifndef DSP_3_XTENSA_PARAMS
#define DSP_3_XTENSA_PARAMS
#endif

#ifndef DSP_3_SIM_CLIENT_FILE
#define DSP_3_SIM_CLIENT_FILE
#endif

// Define the XTSC logger
#ifdef XTSC_LOG
--logging=$(XTSC_SCRIPT_FILE_PATH)/SubSystem.logger.txt
#endif

--no_default_local_mem

--xtensa_core=$(DSP_0_CONFIG)

// Host shared memory name
#ifndef SHARED_RAM_L_NAME
#define SHARED_RAM_L_NAME SharedRAM_L
#endif

--user_state=SHARED_RAM_L_FILE=$(SHARED_RAM_L_NAME)

// Create SystemRAM
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0xe0000000
--set_memory_parm=memory_byte_size=536870912
--set_memory_parm=read_delay=$(SYSTEMRAM_DELAY)
--set_memory_parm=block_read_delay=$(SYSTEMRAM_DELAY)
--set_memory_parm=burst_read_delay=$(SYSTEMRAM_DELAY)
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=$(SYSTEMRAM_DELAY)
--set_memory_parm=block_write_delay=$(SYSTEMRAM_DELAY)
--set_memory_parm=burst_write_delay=$(SYSTEMRAM_DELAY)
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=$(SYSTEMRAM_REQUEST_FIFO_DEPTH)
--create_memory=SystemRAM

// Create SystemROM
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0xd0080000
--set_memory_parm=memory_byte_size=16777216
--set_memory_parm=read_delay=$(SYSTEMROM_DELAY)
--set_memory_parm=block_read_delay=$(SYSTEMROM_DELAY)
--set_memory_parm=burst_read_delay=$(SYSTEMROM_DELAY)
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=$(SYSTEMROM_DELAY)
--set_memory_parm=block_write_delay=$(SYSTEMROM_DELAY)
--set_memory_parm=burst_write_delay=$(SYSTEMROM_DELAY)
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=$(SYSTEMROM_REQUEST_FIFO_DEPTH)
--create_memory=SystemROM

// Create Shared_RAM_L
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0x00000000
--set_memory_parm=memory_byte_size=536870912
--set_memory_parm=read_delay=$(SHARED_RAM_L_DELAY)
--set_memory_parm=block_read_delay=$(SHARED_RAM_L_DELAY)
--set_memory_parm=burst_read_delay=$(SHARED_RAM_L_DELAY)
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=$(SHARED_RAM_L_DELAY)
--set_memory_parm=block_write_delay=$(SHARED_RAM_L_DELAY)
--set_memory_parm=burst_write_delay=$(SHARED_RAM_L_DELAY)
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=$(SHARED_RAM_L_REQUEST_FIFO_DEPTH)
--set_memory_parm=host_shared_memory=true
--set_memory_parm=shared_memory_name=$(SHARED_RAM_L_NAME)
--create_memory=Shared_RAM_L

// Instantiate DSP_0's components
#include "$(XTSC_SCRIPT_FILE_PATH)/DSP_0.inc"

// Instantiate DSP_1's components
#include "$(XTSC_SCRIPT_FILE_PATH)/DSP_1.inc"

// Instantiate DSP_2's components
#include "$(XTSC_SCRIPT_FILE_PATH)/DSP_2.inc"

// Instantiate DSP_3's components
#include "$(XTSC_SCRIPT_FILE_PATH)/DSP_3.inc"

// Instantiate inter-processor interconnect

// Create inbound arbiter for DSP_0
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=11
--set_arbiter_parm=immediate_timing=false
--set_arbiter_parm=arbitration_phase=400
--create_arbiter=DSP_0_inbound_arb

// Connect the inbound arbiter to the inbound router
--connect=DSP_0_inbound_arb,master_port,slave_port,DSP_0_inbound_rte

// Create outbound router for DSP_0 
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/DSP_0_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=immediate_timing=false
--create_router=DSP_0_outbound_rte

// Create outbound router for DSP_0 idma
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/DSP_0_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=immediate_timing=false
--create_router=DSP_0_idma_outbound_rte

// Connect DSP_0's pif/datamaster/outbound_arb and idma to DSP_0's outbound router
--connect=DSP_0,pif,slave_port,DSP_0_outbound_rte
--connect=DSP_0,idma0,slave_port,DSP_0_idma_outbound_rte

// Create inbound arbiter for DSP_1
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=11
--set_arbiter_parm=immediate_timing=false
--set_arbiter_parm=arbitration_phase=400
--create_arbiter=DSP_1_inbound_arb

// Connect the inbound arbiter to the inbound router
--connect=DSP_1_inbound_arb,master_port,slave_port,DSP_1_inbound_rte

// Create outbound router for DSP_1 
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/DSP_1_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=immediate_timing=false
--create_router=DSP_1_outbound_rte

// Create outbound router for DSP_1 idma
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/DSP_1_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=immediate_timing=false
--create_router=DSP_1_idma_outbound_rte

// Connect DSP_1's pif/datamaster/outbound_arb and idma to DSP_1's outbound router
--connect=DSP_1,pif,slave_port,DSP_1_outbound_rte
--connect=DSP_1,idma0,slave_port,DSP_1_idma_outbound_rte

// Create inbound arbiter for DSP_2
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=11
--set_arbiter_parm=immediate_timing=false
--set_arbiter_parm=arbitration_phase=400
--create_arbiter=DSP_2_inbound_arb

// Connect the inbound arbiter to the inbound router
--connect=DSP_2_inbound_arb,master_port,slave_port,DSP_2_inbound_rte

// Create outbound router for DSP_2 
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/DSP_2_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=immediate_timing=false
--create_router=DSP_2_outbound_rte

// Create outbound router for DSP_2 idma
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/DSP_2_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=immediate_timing=false
--create_router=DSP_2_idma_outbound_rte

// Connect DSP_2's pif/datamaster/outbound_arb and idma to DSP_2's outbound router
--connect=DSP_2,pif,slave_port,DSP_2_outbound_rte
--connect=DSP_2,idma0,slave_port,DSP_2_idma_outbound_rte

// Create inbound arbiter for DSP_3
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=11
--set_arbiter_parm=immediate_timing=false
--set_arbiter_parm=arbitration_phase=400
--create_arbiter=DSP_3_inbound_arb

// Connect the inbound arbiter to the inbound router
--connect=DSP_3_inbound_arb,master_port,slave_port,DSP_3_inbound_rte

// Create outbound router for DSP_3 
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/DSP_3_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=immediate_timing=false
--create_router=DSP_3_outbound_rte

// Create outbound router for DSP_3 idma
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/DSP_3_outbound_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--set_router_parm=immediate_timing=false
--create_router=DSP_3_idma_outbound_rte

// Connect DSP_3's pif/datamaster/outbound_arb and idma to DSP_3's outbound router
--connect=DSP_3,pif,slave_port,DSP_3_outbound_rte
--connect=DSP_3,idma0,slave_port,DSP_3_idma_outbound_rte

// Create TestBenchMaster xtsc_master
--set_master_parm=script_file=$(XTSC_SCRIPT_FILE_PATH)/TestBenchMaster.vec
--create_master=TestBenchMaster

// Create router for the xtsc_master
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/TestBenchMaster_rte.tab
--set_router_parm=default_port_num=0
--set_router_parm=num_slaves=1
--create_router=TestBenchMaster_rte

// Connect the TestBenchMaster to the router
--connect=TestBenchMaster,master_port,slave_port,TestBenchMaster_rte

// Bus arbiter masters - DSP_0, DSP_1, DSP_2, DSP_3, L2 (optional) and the TestBenchMaster
--set_arbiter_parm=num_masters=9
--set_arbiter_parm=route_id_lsb=5
--set_arbiter_parm=master_byte_widths=16,16,16,16,16,16,16,16,16
--set_arbiter_parm=slave_byte_width=16
--create_arbiter=BUS_arb

// Create common bus router
// Bus router slaves - DSP_0, DSP_1, DSP_2, DSP_3
//                     DSP_2's MMIO, DSP_0's MMIO, DSP_3's MMIO, DSP_1's MMIO,
//                     SystemRAM, SystemROM, Shared_RAM_L
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/bus_rte.tab
--set_router_parm=immediate_timing=true
--set_router_parm=num_slaves=7
--set_router_parm=default_port_num=666
--create_router=BUS_rte

// Instantiate the common bus by connecting the BUS router and arbiter
--connect=BUS_arb,master_port,slave_port,BUS_rte

// Connect the common BUS  router to all processors
--connect=BUS_rte,master_port[0],slave_port[0],DSP_0_inbound_arb
--connect=BUS_rte,master_port[1],slave_port[0],DSP_1_inbound_arb
--connect=BUS_rte,master_port[2],slave_port[0],DSP_2_inbound_arb
--connect=BUS_rte,master_port[3],slave_port[0],DSP_3_inbound_arb
// Connect SystemRAM, SystemROM, DeviceMemories (optional),
// L2 (optional) to the common bus router
--connect=BUS_rte,master_port[4],slave_port[0],SystemRAM
--connect=BUS_rte,master_port[5],slave_port[0],SystemROM
// Connect DeviceMemories to the common bus router
--connect=BUS_rte,master_port[6],slave_port[0],Shared_RAM_L

// Connect processor's outbound router to BUS  arbiter
--connect=DSP_0_outbound_rte,master_port[0],slave_port[0],BUS_arb
--connect=DSP_0_idma_outbound_rte,master_port[0],slave_port[1],BUS_arb
--connect=DSP_1_outbound_rte,master_port[0],slave_port[2],BUS_arb
--connect=DSP_1_idma_outbound_rte,master_port[0],slave_port[3],BUS_arb
--connect=DSP_2_outbound_rte,master_port[0],slave_port[4],BUS_arb
--connect=DSP_2_idma_outbound_rte,master_port[0],slave_port[5],BUS_arb
--connect=DSP_3_outbound_rte,master_port[0],slave_port[6],BUS_arb
--connect=DSP_3_idma_outbound_rte,master_port[0],slave_port[7],BUS_arb

// Connect the TestBench xtsc_master router to the last port of the BUS_arb
--connect=TestBenchMaster_rte,master_port[0],slave_port[8],BUS_arb

// Connect the outbound router to other processors (if fast-paths present)
