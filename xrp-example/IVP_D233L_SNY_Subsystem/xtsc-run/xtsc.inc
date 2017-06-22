// Edit HERE according to your system
#ifndef SYSRAM_LATENCY
#define SYSRAM_LATENCY=64
#endif
#ifndef SYSROM_LATENCY
#define SYSROM_LATENCY=64
#endif

// DO NOT EDIT BELOW
// Defaults
#ifndef HOST_CORE
#define HOST_CORE=D_233L_pif128
#endif
#ifndef SUBSYSTEM_CORE
#define SUBSYSTEM_CORE=IVPEP_SNY_IVP_AL2_P1
#endif
#ifndef HOST_ELF
#define HOST_ELF=Image.elf
#endif
#ifndef SUBSYSTEM_ELF
#define SUBSYSTEM_ELF=
#endif

--set_xtsc_parm=lua_script_files=$(XTSC_SCRIPT_FILE_PATH)/sim_cntrl.lua
--logging=$(XTSC_SCRIPT_FILE_PATH)/TextLogger.txt
--no_default_mem

// Create Cores
--xtensa_core=$(HOST_CORE)
--xtensa_params=
--set_core_parm=ProcessorID=0
--set_core_parm=SimStaticVectorSelect=0
--core_program=$(HOST_ELF)
#ifdef HOST_DEBUG
--core_debug=nowait,sync
#endif
--create_core=HOST0
  
--xtensa_core=$(SUBSYSTEM_CORE)
--xtensa_params=
--set_core_parm=ProcessorID=1
//--set_core_parm=SimStaticVectorSelect=1
--core_program=$(SUBSYSTEM_ELF)
#ifdef IVP_DEBUG
--core_debug=nowait,sync
#endif
--create_core=IVP0

// Create SharedRAM
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0xf0000000
--set_memory_parm=memory_byte_size=16777216
--set_memory_parm=read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=burst_read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=burst_write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=255
--create_memory=SharedRAM

// Create SharedRAM 2
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0xf2000000
--set_memory_parm=memory_byte_size=16777216
--set_memory_parm=read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=burst_read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=burst_write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=255
--create_memory=SharedRAM2

// Create SystemRAM
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0x60000000
 --set_memory_parm=memory_byte_size=536870912 //512MB
--set_memory_parm=read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=burst_read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=burst_write_delay=$(SYSRAM_LATENCY)
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
--set_memory_parm=read_delay=$(SYSROM_LATENCY)
--set_memory_parm=block_read_delay=$(SYSROM_LATENCY)
--set_memory_parm=burst_read_delay=$(SYSROM_LATENCY)
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=$(SYSROM_LATENCY)
--set_memory_parm=block_write_delay=$(SYSROM_LATENCY)
--set_memory_parm=burst_write_delay=$(SYSROM_LATENCY)
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=255
--create_memory=SystemROM

// Create SystemRAM_L
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0x00050000
--set_memory_parm=memory_byte_size=0x0ffb0000 //256MB
--set_memory_parm=read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=burst_read_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=burst_write_delay=$(SYSRAM_LATENCY)
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=255
--create_memory=SystemRAM_L

// Create SystemROM_L
--memory_port=pif
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=start_byte_address=0xfe000000
--set_memory_parm=memory_byte_size=16777216
--set_memory_parm=read_delay=$(SYSROM_LATENCY)
--set_memory_parm=block_read_delay=$(SYSROM_LATENCY)
--set_memory_parm=burst_read_delay=$(SYSROM_LATENCY)
--set_memory_parm=block_read_repeat=1
--set_memory_parm=burst_read_repeat=1
--set_memory_parm=write_delay=$(SYSROM_LATENCY)
--set_memory_parm=block_write_delay=$(SYSROM_LATENCY)
--set_memory_parm=burst_write_delay=$(SYSROM_LATENCY)
--set_memory_parm=block_write_repeat=1
--set_memory_parm=burst_write_repeat=1
--set_memory_parm=request_fifo_depth=255
--create_memory=SystemROM_L


// Create proc IVP0's uDMA
--set_xtsc_udma_parm=ram_byte_width=64
--set_xtsc_udma_parm=ram_start_addresses=0x00010000, 0x00030000
--set_xtsc_udma_parm=ram_byte_sizes=65536, 65536
--set_xtsc_udma_parm=pif_byte_width=16
--create_xtsc_udma=IVP0_uDMA

// Connect IVP0's RER/WER lookup interface to the uDMA
--connect=IVP0,IVP_RER,rer_export,IVP0_uDMA
--connect=IVP0,IVP_WER,wer_export,IVP0_uDMA

// Create IVP0 INSTRAM0
--memory_port=iram0
--xtensa-core=$(SUBSYSTEM_CORE)
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=16
--set_memory_parm=immediate_timing=true
--set_memory_parm=start_byte_address=0x00040000
--set_memory_parm=memory_byte_size=8192
--create_memory=IVP0_INSTRAM0

// Create IVP0 INSTRAM0 arbiters
--set_arbiter_parm=num_masters=1
--set_arbiter_parm=route_id_lsb=10
--set_arbiter_parm=response_delay=0
--create_arbiter=IVP0_INSTRAM0_arb

// Connect IVP0 INSTRAM0 port to the INSTRAM0 arbiters
--connect_core_arbiter=IVP0,iram0,0,IVP0_INSTRAM0_arb

// Connect IVP0 INSTRAM0 arbiter to INSTRAM0
--connect_arbiter_memory=IVP0_INSTRAM0_arb,IVP0_INSTRAM0

// Create IVP0 DATARAM0 bank 0
--memory_port=dram0
--xtensa-core=$(SUBSYSTEM_CORE)
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=64
--set_memory_parm=immediate_timing=true
--set_memory_parm=start_byte_address=0x00010000
--set_memory_parm=memory_byte_size=65536
--create_memory=IVP0_DATARAM0_b0

// Create IVP0 DATARAM0 bank 1
--memory_port=dram0
--xtensa-core=$(SUBSYSTEM_CORE)
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=64
--set_memory_parm=immediate_timing=true
--set_memory_parm=start_byte_address=0x00010000
--set_memory_parm=memory_byte_size=65536
--create_memory=IVP0_DATARAM0_b1

// Create IVP0 DATARAM0 arbiters

// Create IVP0_DATARAM0 bank 0 arbiter
--set_arbiter_parm=num_masters=3
--set_arbiter_parm=route_id_lsb=10
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=arbitration_policy=1,1,0;1,1,0;0,0,0
--create_arbiter=IVP0_DATARAM0_b0_arb

// Create IVP0_DATARAM0 bank 1 arbiter
--set_arbiter_parm=num_masters=3
--set_arbiter_parm=route_id_lsb=10
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=arbitration_policy=1,1,0;1,1,0;0,0,0
--create_arbiter=IVP0_DATARAM0_b1_arb

// Connect IVP0 DATARAM0 arbiters to DATARAM0
--connect_arbiter_memory=IVP0_DATARAM0_b0_arb,IVP0_DATARAM0_b0
--connect_arbiter_memory=IVP0_DATARAM0_b1_arb,IVP0_DATARAM0_b1

// Create IVP0's DATARAM0 bank routers

// Create port p0's router
--set_router_parm=num_slaves=2
--set_router_parm=address_routing_bits=6,6
--set_router_parm=master_byte_width=64
--set_router_parm=immediate_timing=true
--create_router=IVP0_dram0p0_rte

// Create port p1's router
--set_router_parm=num_slaves=2
--set_router_parm=address_routing_bits=6,6
--set_router_parm=master_byte_width=64
--set_router_parm=immediate_timing=true
--create_router=IVP0_dram0p1_rte

// Connect IVP0's dram0 ports to the dram0 bank routers
--connect_core_router=IVP0,dram0p0,IVP0_dram0p0_rte
--connect_core_router=IVP0,dram0p1,IVP0_dram0p1_rte

// Connect IVP0's DATARAM0 bank routers to DATARAM0 bank arbiters
--connect_router_arbiter=IVP0_dram0p0_rte,0,0,IVP0_DATARAM0_b0_arb
--connect_router_arbiter=IVP0_dram0p0_rte,1,0,IVP0_DATARAM0_b1_arb
--connect_router_arbiter=IVP0_dram0p1_rte,0,1,IVP0_DATARAM0_b0_arb
--connect_router_arbiter=IVP0_dram0p1_rte,1,1,IVP0_DATARAM0_b1_arb

// Create IVP0 DATARAM1 bank 0
--memory_port=dram1
--xtensa-core=$(SUBSYSTEM_CORE)
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=64
--set_memory_parm=immediate_timing=true
--set_memory_parm=start_byte_address=0x00030000
--set_memory_parm=memory_byte_size=65536
--create_memory=IVP0_DATARAM1_b0

// Create IVP0 DATARAM1 bank 1
--memory_port=dram1
--xtensa-core=$(SUBSYSTEM_CORE)
--set_memory_parm=num_ports=1
--set_memory_parm=byte_width=64
--set_memory_parm=immediate_timing=true
--set_memory_parm=start_byte_address=0x00030000
--set_memory_parm=memory_byte_size=65536
--create_memory=IVP0_DATARAM1_b1

// Create IVP0 DATARAM1 arbiters

// Create IVP0_DATARAM1 bank 0 arbiter
--set_arbiter_parm=num_masters=3
--set_arbiter_parm=route_id_lsb=10
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=arbitration_policy=1,1,0;1,1,0;0,0,0
--create_arbiter=IVP0_DATARAM1_b0_arb

// Create IVP0_DATARAM1 bank 1 arbiter
--set_arbiter_parm=num_masters=3
--set_arbiter_parm=route_id_lsb=10
--set_arbiter_parm=response_delay=0
--set_arbiter_parm=arbitration_policy=1,1,0;1,1,0;0,0,0
--create_arbiter=IVP0_DATARAM1_b1_arb

// Connect IVP0 DATARAM1 arbiters to DATARAM1
--connect_arbiter_memory=IVP0_DATARAM1_b0_arb,IVP0_DATARAM1_b0
--connect_arbiter_memory=IVP0_DATARAM1_b1_arb,IVP0_DATARAM1_b1

// Create IVP0's DATARAM1 bank routers

// Create port p0's router
--set_router_parm=num_slaves=2
--set_router_parm=address_routing_bits=6,6
--set_router_parm=master_byte_width=64
--set_router_parm=immediate_timing=true
--create_router=IVP0_dram1p0_rte

// Create port p1's router
--set_router_parm=num_slaves=2
--set_router_parm=address_routing_bits=6,6
--set_router_parm=master_byte_width=64
--set_router_parm=immediate_timing=true
--create_router=IVP0_dram1p1_rte

// Connect IVP0's dram1 ports to the dram1 bank routers
--connect_core_router=IVP0,dram1p0,IVP0_dram1p0_rte
--connect_core_router=IVP0,dram1p1,IVP0_dram1p1_rte

// Connect IVP0's DATARAM1 bank routers to DATARAM1 bank arbiters
--connect_router_arbiter=IVP0_dram1p0_rte,0,0,IVP0_DATARAM1_b0_arb
--connect_router_arbiter=IVP0_dram1p0_rte,1,0,IVP0_DATARAM1_b1_arb
--connect_router_arbiter=IVP0_dram1p1_rte,0,1,IVP0_DATARAM1_b0_arb
--connect_router_arbiter=IVP0_dram1p1_rte,1,1,IVP0_DATARAM1_b1_arb

// Connect IVP0 uDMA
// Create first level IVP0 uDMA router to route to the DATARAMs
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/IVP0_udma_rte.tab
--set_router_parm=num_slaves=2
--set_router_parm=immediate_timing=true
--create_router=IVP0_udma_rte

// Connect IVP0 uDMA
--connect=IVP0_uDMA,ram_master_port,slave_port,IVP0_udma_rte

// Create second level IVP0 uDMA routers to route to the DATARAM banks
// Create uDMA DATARAM0 bank router
--set_router_parm=num_slaves=2
--set_router_parm=address_routing_bits=6,6
--set_router_parm=master_byte_width=64
--set_router_parm=immediate_timing=true
--create_router=IVP0_udma_dataram0_bank_rte

// Connect the first level IVP0 uDMA router to the
// second level uDMA DATARAM0 bank router
--connect_router_router=IVP0_udma_rte,0,IVP0_udma_dataram0_bank_rte

// Connect the uDMA DATARAM0 bank router to DATARAM0's bank arbiters
--connect_router_arbiter=IVP0_udma_dataram0_bank_rte,0,2,IVP0_DATARAM0_b0_arb
--connect_router_arbiter=IVP0_udma_dataram0_bank_rte,1,2,IVP0_DATARAM0_b1_arb

// Create uDMA DATARAM1 bank router
--set_router_parm=num_slaves=2
--set_router_parm=address_routing_bits=6,6
--set_router_parm=master_byte_width=64
--set_router_parm=immediate_timing=true
--create_router=IVP0_udma_dataram1_bank_rte

// Connect the first level IVP0 uDMA router to the
// second level uDMA DATARAM1 bank router
--connect_router_router=IVP0_udma_rte,1,IVP0_udma_dataram1_bank_rte

// Connect the uDMA DATARAM1 bank router to DATARAM1's bank arbiters
--connect_router_arbiter=IVP0_udma_dataram1_bank_rte,0,2,IVP0_DATARAM1_b0_arb
--connect_router_arbiter=IVP0_udma_dataram1_bank_rte,1,2,IVP0_DATARAM1_b1_arb

// Connect the uDMA sync and error interrupt
--connect=IVP0_uDMA,sync_intr_port,BInterrupt11,IVP0
--connect=IVP0_uDMA,error_intr_port,BInterrupt12,IVP0

// Create outbound PIF arbiter for IVP0
--set_arbiter_parm=num_masters=2
--set_arbiter_parm=route_id_lsb=0
--set_arbiter_parm=arbitration_phase=600
--set_arbiter_parm=master_byte_widths=16,16
--set_arbiter_parm=slave_byte_width=16
--create_arbiter=IVP0_outbound_pif_arb

// Connect to outbound PIF of proc IVP0
--connect_core_arbiter=IVP0,pif,0,IVP0_outbound_pif_arb

// Create outbound PIF router for IVP0
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/IVP0_outbound_pif_rte.tab
--set_router_parm=num_slaves=1
--set_router_parm=immediate_timing=true
--create_router=IVP0_outbound_pif_rte

// Connect IVP0's uDMA to IVP0's outbound PIF arbiter
--connect=IVP0_uDMA,pif_master_port,slave_port[1],IVP0_outbound_pif_arb

// Connect IVP0's outbound PIF arbiter to IVP0's outbound PIF router
--connect_arbiter_router=IVP0_outbound_pif_arb,IVP0_outbound_pif_rte

// Create common bus arbiter
// Bus arbiter masters - IVP0
--set_arbiter_parm=num_masters=2
--set_arbiter_parm=route_id_lsb=1
--set_arbiter_parm=master_byte_widths=16,16
--set_arbiter_parm=slave_byte_width=16
--create_arbiter=BUS_arb

// Create common bus router
// Bus router slaves - 
//                     SystemRAM, SystemROM
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/bus_rte.tab
--set_router_parm=immediate_timing=true
--set_router_parm=num_slaves=8
--create_router=BUS_rte

// Instantiate the common bus by connecting the BUS router and arbiter
--connect_arbiter_router=BUS_arb,BUS_rte

// Connect the common BUS router to all processors and
// their local MMIO (if defined)
// Connect SystemRAM, SystemROM to the common bus router
--connect_router_memory=BUS_rte,0,SystemRAM
--connect_router_memory=BUS_rte,1,SystemROM
--connect_router_memory=BUS_rte,2,SharedRAM
--connect_router_memory=BUS_rte,3,SystemRAM_L
--connect_router_memory=BUS_rte,4,SystemROM_L
--connect_router_memory=BUS_rte,7,SharedRAM2

// Connect processor's outbound PIF router to BUS arbiter
--connect_router_arbiter=IVP0_outbound_pif_rte,0,0,BUS_arb

// Connect processor's outbound PIF to BUS arbiter
--connect_core_arbiter=HOST0,pif,1,BUS_arb

// Connect the outbound PIF router to other processors (if present)

// Connect to inbound PIF port of processors
--connect_router_core=BUS_rte,6,IVP0

// Connect MMIO to IVP/HOST
// MMIO to interrupt IVP/HOST
-set_mmio_parm=definition_file=$(XTSC_SCRIPT_FILE_PATH)/mmio.def
-set_mmio_parm=swizzle_bytes=false
-create_mmio=MMIO
--connect_router_mmio=BUS_rte,5,MMIO


-connect=MMIO,ivp_breset,BReset,IVP0
-connect=MMIO,ivp_runstall,RunStall,IVP0
-connect=MMIO,ivp_statvectorsel,StatVectorSel,IVP0
// IMPWIRE: only if GPIO32
//-set_wire_parm=bit_width=32
//-create_wire=MMIO_to_IVP0
//-connect=MMIO,ivp_impwire,wire_write,MMIO_to_IVP0
//-connect=MMIO_to_IVP0,wire_read,IMPWIRE,IVP0
-connect=MMIO,ivp_interrupt,BInterrupt,IVP0
-connect=MMIO,ivp_interrupt00,BInterrupt00,IVP0
-connect=MMIO,ivp_interrupt01,BInterrupt01,IVP0
-connect=MMIO,ivp_interrupt02,BInterrupt02,IVP0
-connect=MMIO,ivp_interrupt03,BInterrupt03,IVP0
-connect=MMIO,ivp_interrupt04,BInterrupt04,IVP0
-connect=MMIO,ivp_interrupt05,BInterrupt05,IVP0
-connect=MMIO,ivp_interrupt06,BInterrupt06,IVP0
-connect=MMIO,ivp_interrupt07,BInterrupt07,IVP0
-connect=MMIO,ivp_interrupt08,BInterrupt08,IVP0
-connect=MMIO,ivp_interrupt09,BInterrupt09,IVP0
-connect=MMIO,ivp_interrupt10,BInterrupt10,IVP0
-connect=MMIO,ivp_interrupt11,BInterrupt11,IVP0
-connect=MMIO,ivp_interrupt12,BInterrupt12,IVP0
-connect=IVP0,PWaitMode,ivp_pwaitmode,MMIO
// EXPSTATE: only if GPIO32
//-connect=IVP0,EXPSTATE,ivp_expstate,MMIO

-connect=MMIO,host_breset,BReset,HOST0
-connect=MMIO,host_runstall,RunStall,HOST0
-connect=MMIO,host_statvectorsel,StatVectorSel,HOST0
// IMPWIRE: only if GPIO32
-set_wire_parm=bit_width=32
-create_wire=MMIO_to_HOST0
-connect=MMIO,host_impwire,wire_write,MMIO_to_HOST0
-connect=MMIO_to_HOST0,wire_read,IMPWIRE,HOST0
-connect=MMIO,host_interrupt,BInterrupt,HOST0
-connect=MMIO,host_interrupt00,BInterrupt00,HOST0
-connect=MMIO,host_interrupt01,BInterrupt01,HOST0
-connect=MMIO,host_interrupt02,BInterrupt02,HOST0
-connect=MMIO,host_interrupt03,BInterrupt03,HOST0
-connect=MMIO,host_interrupt04,BInterrupt04,HOST0
-connect=MMIO,host_interrupt05,BInterrupt05,HOST0
-connect=MMIO,host_interrupt06,BInterrupt06,HOST0
-connect=MMIO,host_interrupt07,BInterrupt07,HOST0
-connect=MMIO,host_interrupt08,BInterrupt08,HOST0
-connect=MMIO,host_interrupt09,BInterrupt09,HOST0
-connect=MMIO,host_interrupt10,BInterrupt10,HOST0
-connect=MMIO,host_interrupt11,BInterrupt11,HOST0
-connect=MMIO,host_interrupt12,BInterrupt12,HOST0
-connect=MMIO,host_interrupt13,BInterrupt13,HOST0
-connect=MMIO,host_interrupt14,BInterrupt14,HOST0
-connect=MMIO,host_interrupt15,BInterrupt15,HOST0
-connect=MMIO,host_interrupt16,BInterrupt16,HOST0
-connect=HOST0,PWaitMode,host_pwaitmode,MMIO
-connect=HOST0,EXPSTATE,host_expstate,MMIO

