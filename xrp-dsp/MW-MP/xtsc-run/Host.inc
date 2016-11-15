// Build Host's components

// Create proc Host
--xtensa_core=D_233L_pif128_LC
--xtensa_params=
--set_core_parm=ProcessorID=2
--set_core_parm=SimStaticVectorSelect=0
--set_core_parm=SimClientFile=$(Host_SIM_CLIENT_FILE)
--core_args=$(Host_BINARY_ARGS)
--core_program=$(Host_BINARY)
--create_core=Host

// Create Host's MMIO
--set_mmio_parm=definition_file=$(XTSC_SCRIPT_FILE_PATH)/Host_mmio.def
--create_mmio=Host_mmio

// Connect Host's MMIO to the proc
--connect=Host_mmio,Host_intr_reg_0,BInterrupt10,Host
--connect=Host_mmio,Host_intr_reg_1,BInterrupt11,Host
--connect=Host_mmio,Host_intr_reg_2,BInterrupt12,Host
--connect=Host_mmio,Host_BReset,BReset,Host
--connect=Host_mmio,Host_RunStall,RunStall,Host
--connect=Host_mmio,Host_StatVectorSel,StatVectorSel,Host
--connect=Host_mmio,Host_BInterrupt13,BInterrupt13,Host
--connect=Host_mmio,Host_BInterrupt14,BInterrupt14,Host

// Create inbound PIF/MMIO router for Host
--set_router_parm=routing_table=$(XTSC_SCRIPT_FILE_PATH)/Host_inbound_rte.tab
--set_router_parm=default_port_num=666
--set_router_parm=num_slaves=1
--set_router_parm=immediate_timing=true
--create_router=Host_inbound_rte

// Connect the inbound router to the inbound PIF (if defined) or
// local MMIO (if defined)
--connect=Host_inbound_rte,master_port[0],slave_port,Host_mmio

