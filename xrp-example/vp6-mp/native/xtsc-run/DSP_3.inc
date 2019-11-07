// Build DSP_3's components

// Create proc DSP_3
--xtensa_core=$(DSP_3_CONFIG)
--xtensa_params=
--set_core_parm=ProcessorID=3
--set_core_parm=SimStaticVectorSelect=0
--set_core_parm=SimClientFile=$(DSP_3_SIM_CLIENT_FILE)
// Uncomment below for instruction tracing
// --set_core_parm=SimClients=trace --level=6 DSP_3.insn.trace
--core_args=$(DSP_3_BINARY_ARGS)
--core_program=$(DSP_3_BINARY)
--create_core=DSP_3

// Create DSP_3 INSTRAM0
--memory_port=iram0
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=immediate_timing=true
--set_memory_parm=start_byte_address=0xd0000000
--set_memory_parm=memory_byte_size=32768
--create_memory=DSP_3_INSTRAM0

// Create DSP_3 INSTRAM0 arbiters
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=immediate_timing=true
--set_arbiter_parm=response_delay=0
--create_arbiter=DSP_3_INSTRAM0_arb

// Connect DSP_3 INSTRAM0 port to the INSTRAM0 arbiters
--connect=DSP_3,iram0,slave_port[0],DSP_3_INSTRAM0_arb
// Connect DSP_3 INSTRAM0 arbiter to INSTRAM0
--connect=DSP_3_INSTRAM0_arb,master_port,slave_port,DSP_3_INSTRAM0

// Create DSP_3 DATARAM0
--memory_port=dram0
--set_memory_parm=num_ports=16
--set_memory_parm=byte_width=64
--set_memory_parm=immediate_timing=true
--set_memory_parm=start_byte_address=0xcffc0000
--set_memory_parm=memory_byte_size=262144
--create_memory=DSP_3_DATARAM0

// Create DSP_3 DATARAM0 arbiters
// Create DSP_3_DATARAM0 bank 0 sub-bank 0 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b0_s0_arb

// Create DSP_3_DATARAM0 bank 0 sub-bank 1 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b0_s1_arb

// Create DSP_3_DATARAM0 bank 0 sub-bank 2 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b0_s2_arb

// Create DSP_3_DATARAM0 bank 0 sub-bank 3 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b0_s3_arb

// Create DSP_3_DATARAM0 bank 0 sub-bank 4 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b0_s4_arb

// Create DSP_3_DATARAM0 bank 0 sub-bank 5 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b0_s5_arb

// Create DSP_3_DATARAM0 bank 0 sub-bank 6 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b0_s6_arb

// Create DSP_3_DATARAM0 bank 0 sub-bank 7 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b0_s7_arb

// Create DSP_3_DATARAM0 bank 1 sub-bank 0 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b1_s0_arb

// Create DSP_3_DATARAM0 bank 1 sub-bank 1 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b1_s1_arb

// Create DSP_3_DATARAM0 bank 1 sub-bank 2 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b1_s2_arb

// Create DSP_3_DATARAM0 bank 1 sub-bank 3 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b1_s3_arb

// Create DSP_3_DATARAM0 bank 1 sub-bank 4 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b1_s4_arb

// Create DSP_3_DATARAM0 bank 1 sub-bank 5 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b1_s5_arb

// Create DSP_3_DATARAM0 bank 1 sub-bank 6 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b1_s6_arb

// Create DSP_3_DATARAM0 bank 1 sub-bank 7 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM0_b1_s7_arb

// Connect DSP_3 dram0 ports to DATARAM0 arbiter
--connect=DSP_3,dram0b0s00,slave_port[0],DSP_3_DATARAM0_b0_s0_arb
--connect=DSP_3,dram0b0s01,slave_port[0],DSP_3_DATARAM0_b0_s1_arb
--connect=DSP_3,dram0b0s02,slave_port[0],DSP_3_DATARAM0_b0_s2_arb
--connect=DSP_3,dram0b0s03,slave_port[0],DSP_3_DATARAM0_b0_s3_arb
--connect=DSP_3,dram0b0s04,slave_port[0],DSP_3_DATARAM0_b0_s4_arb
--connect=DSP_3,dram0b0s05,slave_port[0],DSP_3_DATARAM0_b0_s5_arb
--connect=DSP_3,dram0b0s06,slave_port[0],DSP_3_DATARAM0_b0_s6_arb
--connect=DSP_3,dram0b0s07,slave_port[0],DSP_3_DATARAM0_b0_s7_arb
--connect=DSP_3,dram0b1s00,slave_port[0],DSP_3_DATARAM0_b1_s0_arb
--connect=DSP_3,dram0b1s01,slave_port[0],DSP_3_DATARAM0_b1_s1_arb
--connect=DSP_3,dram0b1s02,slave_port[0],DSP_3_DATARAM0_b1_s2_arb
--connect=DSP_3,dram0b1s03,slave_port[0],DSP_3_DATARAM0_b1_s3_arb
--connect=DSP_3,dram0b1s04,slave_port[0],DSP_3_DATARAM0_b1_s4_arb
--connect=DSP_3,dram0b1s05,slave_port[0],DSP_3_DATARAM0_b1_s5_arb
--connect=DSP_3,dram0b1s06,slave_port[0],DSP_3_DATARAM0_b1_s6_arb
--connect=DSP_3,dram0b1s07,slave_port[0],DSP_3_DATARAM0_b1_s7_arb
// Connect DSP_3 DATARAM0 arbiters to DATARAM0 ports
--connect=DSP_3_DATARAM0_b0_s0_arb,master_port,slave_port[0],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b0_s1_arb,master_port,slave_port[1],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b0_s2_arb,master_port,slave_port[2],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b0_s3_arb,master_port,slave_port[3],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b0_s4_arb,master_port,slave_port[4],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b0_s5_arb,master_port,slave_port[5],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b0_s6_arb,master_port,slave_port[6],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b0_s7_arb,master_port,slave_port[7],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b1_s0_arb,master_port,slave_port[8],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b1_s1_arb,master_port,slave_port[9],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b1_s2_arb,master_port,slave_port[10],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b1_s3_arb,master_port,slave_port[11],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b1_s4_arb,master_port,slave_port[12],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b1_s5_arb,master_port,slave_port[13],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b1_s6_arb,master_port,slave_port[14],DSP_3_DATARAM0
--connect=DSP_3_DATARAM0_b1_s7_arb,master_port,slave_port[15],DSP_3_DATARAM0

// Create DSP_3 DATARAM1
--memory_port=dram1
--set_memory_parm=num_ports=16
--set_memory_parm=byte_width=64
--set_memory_parm=immediate_timing=true
--set_memory_parm=start_byte_address=0xcff80000
--set_memory_parm=memory_byte_size=262144
--create_memory=DSP_3_DATARAM1

// Create DSP_3 DATARAM1 arbiters
// Create DSP_3_DATARAM1 bank 0 sub-bank 0 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b0_s0_arb

// Create DSP_3_DATARAM1 bank 0 sub-bank 1 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b0_s1_arb

// Create DSP_3_DATARAM1 bank 0 sub-bank 2 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b0_s2_arb

// Create DSP_3_DATARAM1 bank 0 sub-bank 3 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b0_s3_arb

// Create DSP_3_DATARAM1 bank 0 sub-bank 4 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b0_s4_arb

// Create DSP_3_DATARAM1 bank 0 sub-bank 5 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b0_s5_arb

// Create DSP_3_DATARAM1 bank 0 sub-bank 6 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b0_s6_arb

// Create DSP_3_DATARAM1 bank 0 sub-bank 7 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b0_s7_arb

// Create DSP_3_DATARAM1 bank 1 sub-bank 0 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b1_s0_arb

// Create DSP_3_DATARAM1 bank 1 sub-bank 1 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b1_s1_arb

// Create DSP_3_DATARAM1 bank 1 sub-bank 2 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b1_s2_arb

// Create DSP_3_DATARAM1 bank 1 sub-bank 3 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b1_s3_arb

// Create DSP_3_DATARAM1 bank 1 sub-bank 4 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b1_s4_arb

// Create DSP_3_DATARAM1 bank 1 sub-bank 5 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b1_s5_arb

// Create DSP_3_DATARAM1 bank 1 sub-bank 6 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b1_s6_arb

// Create DSP_3_DATARAM1 bank 1 sub-bank 7 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=16
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=DSP_3_DATARAM1_b1_s7_arb

// Connect DSP_3 dram1 ports to DATARAM1 arbiter
--connect=DSP_3,dram1b0s00,slave_port[0],DSP_3_DATARAM1_b0_s0_arb
--connect=DSP_3,dram1b0s01,slave_port[0],DSP_3_DATARAM1_b0_s1_arb
--connect=DSP_3,dram1b0s02,slave_port[0],DSP_3_DATARAM1_b0_s2_arb
--connect=DSP_3,dram1b0s03,slave_port[0],DSP_3_DATARAM1_b0_s3_arb
--connect=DSP_3,dram1b0s04,slave_port[0],DSP_3_DATARAM1_b0_s4_arb
--connect=DSP_3,dram1b0s05,slave_port[0],DSP_3_DATARAM1_b0_s5_arb
--connect=DSP_3,dram1b0s06,slave_port[0],DSP_3_DATARAM1_b0_s6_arb
--connect=DSP_3,dram1b0s07,slave_port[0],DSP_3_DATARAM1_b0_s7_arb
--connect=DSP_3,dram1b1s00,slave_port[0],DSP_3_DATARAM1_b1_s0_arb
--connect=DSP_3,dram1b1s01,slave_port[0],DSP_3_DATARAM1_b1_s1_arb
--connect=DSP_3,dram1b1s02,slave_port[0],DSP_3_DATARAM1_b1_s2_arb
--connect=DSP_3,dram1b1s03,slave_port[0],DSP_3_DATARAM1_b1_s3_arb
--connect=DSP_3,dram1b1s04,slave_port[0],DSP_3_DATARAM1_b1_s4_arb
--connect=DSP_3,dram1b1s05,slave_port[0],DSP_3_DATARAM1_b1_s5_arb
--connect=DSP_3,dram1b1s06,slave_port[0],DSP_3_DATARAM1_b1_s6_arb
--connect=DSP_3,dram1b1s07,slave_port[0],DSP_3_DATARAM1_b1_s7_arb
// Connect DSP_3 DATARAM1 arbiters to DATARAM1 ports
--connect=DSP_3_DATARAM1_b0_s0_arb,master_port,slave_port[0],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b0_s1_arb,master_port,slave_port[1],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b0_s2_arb,master_port,slave_port[2],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b0_s3_arb,master_port,slave_port[3],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b0_s4_arb,master_port,slave_port[4],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b0_s5_arb,master_port,slave_port[5],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b0_s6_arb,master_port,slave_port[6],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b0_s7_arb,master_port,slave_port[7],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b1_s0_arb,master_port,slave_port[8],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b1_s1_arb,master_port,slave_port[9],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b1_s2_arb,master_port,slave_port[10],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b1_s3_arb,master_port,slave_port[11],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b1_s4_arb,master_port,slave_port[12],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b1_s5_arb,master_port,slave_port[13],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b1_s6_arb,master_port,slave_port[14],DSP_3_DATARAM1
--connect=DSP_3_DATARAM1_b1_s7_arb,master_port,slave_port[15],DSP_3_DATARAM1

// Create DSP_3's MMIO
--set_mmio_parm=definition_file=$(XTSC_SCRIPT_FILE_PATH)/DSP_3_mmio.def
--create_mmio=DSP_3_mmio

// Connect DSP_3's MMIO to the proc
--connect=DSP_3_mmio,DSP_3_intr_reg_0,BInterrupt04,DSP_3
--connect=DSP_3_mmio,DSP_3_intr_reg_1,BInterrupt05,DSP_3
--connect=DSP_3_mmio,DSP_3_intr_reg_2,BInterrupt12,DSP_3
--connect=DSP_3_mmio,DSP_3_BReset,BReset,DSP_3
--connect=DSP_3_mmio,DSP_3_RunStall,RunStall,DSP_3
--connect=DSP_3_mmio,DSP_3_StatVectorSel,StatVectorSel,DSP_3

// Create inbound PIF/AXI/MMIO router for DSP_3
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/DSP_3_inbound_rte.tab
--set_router_parm=default_port_num=666
--set_router_parm=num_slaves=2
--create_router=DSP_3_inbound_rte

// Connect the inbound router to the inbound PIF (if defined) or
// local MMIO (if defined)
--connect=DSP_3_inbound_rte,master_port[0],inbound_pif,DSP_3
--connect=DSP_3_inbound_rte,master_port[1],slave_port,DSP_3_mmio

