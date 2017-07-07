// Build P6_0's components

// Create proc P6_0
--xtensa_core=visionp6cnn_ao_exls
--xtensa_params=
--set_core_parm=ProcessorID=0
--set_core_parm=SimStaticVectorSelect=0
--set_core_parm=SimClientFile=$(P6_0_SIM_CLIENT_FILE)
--core_args=$(P6_0_BINARY_ARGS)
--core_program=$(P6_0_BINARY)
--create_core=P6_0

// Create P6_0 DATARAM0
--memory_port=dram0
--set_memory_parm=num_ports=16
--set_memory_parm=byte_width=16
--set_memory_parm=immediate_timing=true
--set_memory_parm=start_byte_address=0x3ffe0000
--set_memory_parm=memory_byte_size=131072
--create_memory=P6_0_DATARAM0

// Create P6_0 DATARAM0 arbiters
// Create P6_0_DATARAM0 bank 0 sub-bank 0 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b0_s0_arb

// Create P6_0_DATARAM0 bank 0 sub-bank 1 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b0_s1_arb

// Create P6_0_DATARAM0 bank 0 sub-bank 2 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b0_s2_arb

// Create P6_0_DATARAM0 bank 0 sub-bank 3 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b0_s3_arb

// Create P6_0_DATARAM0 bank 0 sub-bank 4 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b0_s4_arb

// Create P6_0_DATARAM0 bank 0 sub-bank 5 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b0_s5_arb

// Create P6_0_DATARAM0 bank 0 sub-bank 6 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b0_s6_arb

// Create P6_0_DATARAM0 bank 0 sub-bank 7 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b0_s7_arb

// Create P6_0_DATARAM0 bank 1 sub-bank 0 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b1_s0_arb

// Create P6_0_DATARAM0 bank 1 sub-bank 1 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b1_s1_arb

// Create P6_0_DATARAM0 bank 1 sub-bank 2 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b1_s2_arb

// Create P6_0_DATARAM0 bank 1 sub-bank 3 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b1_s3_arb

// Create P6_0_DATARAM0 bank 1 sub-bank 4 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b1_s4_arb

// Create P6_0_DATARAM0 bank 1 sub-bank 5 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b1_s5_arb

// Create P6_0_DATARAM0 bank 1 sub-bank 6 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b1_s6_arb

// Create P6_0_DATARAM0 bank 1 sub-bank 7 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM0_b1_s7_arb

// Connect P6_0 dram0 ports to DATARAM0 arbiter
--connect=P6_0,dram0b0s00,slave_port[0],P6_0_DATARAM0_b0_s0_arb
--connect=P6_0,dram0b0s01,slave_port[0],P6_0_DATARAM0_b0_s1_arb
--connect=P6_0,dram0b0s02,slave_port[0],P6_0_DATARAM0_b0_s2_arb
--connect=P6_0,dram0b0s03,slave_port[0],P6_0_DATARAM0_b0_s3_arb
--connect=P6_0,dram0b0s04,slave_port[0],P6_0_DATARAM0_b0_s4_arb
--connect=P6_0,dram0b0s05,slave_port[0],P6_0_DATARAM0_b0_s5_arb
--connect=P6_0,dram0b0s06,slave_port[0],P6_0_DATARAM0_b0_s6_arb
--connect=P6_0,dram0b0s07,slave_port[0],P6_0_DATARAM0_b0_s7_arb
--connect=P6_0,dram0b1s00,slave_port[0],P6_0_DATARAM0_b1_s0_arb
--connect=P6_0,dram0b1s01,slave_port[0],P6_0_DATARAM0_b1_s1_arb
--connect=P6_0,dram0b1s02,slave_port[0],P6_0_DATARAM0_b1_s2_arb
--connect=P6_0,dram0b1s03,slave_port[0],P6_0_DATARAM0_b1_s3_arb
--connect=P6_0,dram0b1s04,slave_port[0],P6_0_DATARAM0_b1_s4_arb
--connect=P6_0,dram0b1s05,slave_port[0],P6_0_DATARAM0_b1_s5_arb
--connect=P6_0,dram0b1s06,slave_port[0],P6_0_DATARAM0_b1_s6_arb
--connect=P6_0,dram0b1s07,slave_port[0],P6_0_DATARAM0_b1_s7_arb
// Connect P6_0 DATARAM0 arbiters to DATARAM0 ports
--connect=P6_0_DATARAM0_b0_s0_arb,master_port,slave_port[0],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b0_s1_arb,master_port,slave_port[1],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b0_s2_arb,master_port,slave_port[2],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b0_s3_arb,master_port,slave_port[3],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b0_s4_arb,master_port,slave_port[4],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b0_s5_arb,master_port,slave_port[5],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b0_s6_arb,master_port,slave_port[6],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b0_s7_arb,master_port,slave_port[7],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b1_s0_arb,master_port,slave_port[8],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b1_s1_arb,master_port,slave_port[9],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b1_s2_arb,master_port,slave_port[10],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b1_s3_arb,master_port,slave_port[11],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b1_s4_arb,master_port,slave_port[12],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b1_s5_arb,master_port,slave_port[13],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b1_s6_arb,master_port,slave_port[14],P6_0_DATARAM0
--connect=P6_0_DATARAM0_b1_s7_arb,master_port,slave_port[15],P6_0_DATARAM0

// Create P6_0 DATARAM1
--memory_port=dram1
--set_memory_parm=num_ports=16
--set_memory_parm=byte_width=16
--set_memory_parm=immediate_timing=true
--set_memory_parm=start_byte_address=0x3ffc0000
--set_memory_parm=memory_byte_size=131072
--create_memory=P6_0_DATARAM1

// Create P6_0 DATARAM1 arbiters
// Create P6_0_DATARAM1 bank 0 sub-bank 0 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b0_s0_arb

// Create P6_0_DATARAM1 bank 0 sub-bank 1 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b0_s1_arb

// Create P6_0_DATARAM1 bank 0 sub-bank 2 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b0_s2_arb

// Create P6_0_DATARAM1 bank 0 sub-bank 3 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b0_s3_arb

// Create P6_0_DATARAM1 bank 0 sub-bank 4 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b0_s4_arb

// Create P6_0_DATARAM1 bank 0 sub-bank 5 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b0_s5_arb

// Create P6_0_DATARAM1 bank 0 sub-bank 6 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b0_s6_arb

// Create P6_0_DATARAM1 bank 0 sub-bank 7 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b0_s7_arb

// Create P6_0_DATARAM1 bank 1 sub-bank 0 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b1_s0_arb

// Create P6_0_DATARAM1 bank 1 sub-bank 1 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b1_s1_arb

// Create P6_0_DATARAM1 bank 1 sub-bank 2 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b1_s2_arb

// Create P6_0_DATARAM1 bank 1 sub-bank 3 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b1_s3_arb

// Create P6_0_DATARAM1 bank 1 sub-bank 4 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b1_s4_arb

// Create P6_0_DATARAM1 bank 1 sub-bank 5 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b1_s5_arb

// Create P6_0_DATARAM1 bank 1 sub-bank 6 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b1_s6_arb

// Create P6_0_DATARAM1 bank 1 sub-bank 7 arbiter
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=12
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=immediate_timing=true
--create_arbiter=P6_0_DATARAM1_b1_s7_arb

// Connect P6_0 dram1 ports to DATARAM1 arbiter
--connect=P6_0,dram1b0s00,slave_port[0],P6_0_DATARAM1_b0_s0_arb
--connect=P6_0,dram1b0s01,slave_port[0],P6_0_DATARAM1_b0_s1_arb
--connect=P6_0,dram1b0s02,slave_port[0],P6_0_DATARAM1_b0_s2_arb
--connect=P6_0,dram1b0s03,slave_port[0],P6_0_DATARAM1_b0_s3_arb
--connect=P6_0,dram1b0s04,slave_port[0],P6_0_DATARAM1_b0_s4_arb
--connect=P6_0,dram1b0s05,slave_port[0],P6_0_DATARAM1_b0_s5_arb
--connect=P6_0,dram1b0s06,slave_port[0],P6_0_DATARAM1_b0_s6_arb
--connect=P6_0,dram1b0s07,slave_port[0],P6_0_DATARAM1_b0_s7_arb
--connect=P6_0,dram1b1s00,slave_port[0],P6_0_DATARAM1_b1_s0_arb
--connect=P6_0,dram1b1s01,slave_port[0],P6_0_DATARAM1_b1_s1_arb
--connect=P6_0,dram1b1s02,slave_port[0],P6_0_DATARAM1_b1_s2_arb
--connect=P6_0,dram1b1s03,slave_port[0],P6_0_DATARAM1_b1_s3_arb
--connect=P6_0,dram1b1s04,slave_port[0],P6_0_DATARAM1_b1_s4_arb
--connect=P6_0,dram1b1s05,slave_port[0],P6_0_DATARAM1_b1_s5_arb
--connect=P6_0,dram1b1s06,slave_port[0],P6_0_DATARAM1_b1_s6_arb
--connect=P6_0,dram1b1s07,slave_port[0],P6_0_DATARAM1_b1_s7_arb
// Connect P6_0 DATARAM1 arbiters to DATARAM1 ports
--connect=P6_0_DATARAM1_b0_s0_arb,master_port,slave_port[0],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b0_s1_arb,master_port,slave_port[1],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b0_s2_arb,master_port,slave_port[2],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b0_s3_arb,master_port,slave_port[3],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b0_s4_arb,master_port,slave_port[4],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b0_s5_arb,master_port,slave_port[5],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b0_s6_arb,master_port,slave_port[6],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b0_s7_arb,master_port,slave_port[7],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b1_s0_arb,master_port,slave_port[8],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b1_s1_arb,master_port,slave_port[9],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b1_s2_arb,master_port,slave_port[10],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b1_s3_arb,master_port,slave_port[11],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b1_s4_arb,master_port,slave_port[12],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b1_s5_arb,master_port,slave_port[13],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b1_s6_arb,master_port,slave_port[14],P6_0_DATARAM1
--connect=P6_0_DATARAM1_b1_s7_arb,master_port,slave_port[15],P6_0_DATARAM1

// Create P6_0's MMIO
--set_mmio_parm=definition_file=$(XTSC_SCRIPT_FILE_PATH)/P6_0_mmio.def
--create_mmio=P6_0_mmio

// Connect P6_0's MMIO to the proc
--connect=P6_0_mmio,P6_0_intr_reg_0,BInterrupt04,P6_0
--connect=P6_0_mmio,P6_0_intr_reg_1,BInterrupt05,P6_0
--connect=P6_0_mmio,P6_0_intr_reg_2,BInterrupt12,P6_0
--connect=P6_0_mmio,P6_0_BReset,BReset,P6_0
--connect=P6_0_mmio,P6_0_RunStall,RunStall,P6_0
--connect=P6_0_mmio,P6_0_StatVectorSel,StatVectorSel,P6_0

// Create inbound PIF/MMIO router for P6_0
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/P6_0_inbound_rte.tab
--set_router_parm=default_port_num=666
--set_router_parm=num_slaves=2
--create_router=P6_0_inbound_rte

// Connect the inbound router to the inbound PIF (if defined) or
// local MMIO (if defined)
--connect=P6_0_inbound_rte,master_port[0],inbound_pif,P6_0
--connect=P6_0_inbound_rte,master_port[1],slave_port,P6_0_mmio

