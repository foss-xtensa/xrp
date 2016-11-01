if xtsc.cmd("Host get_parameter_value SimTurbo") == "1" then
  xtsc.cmd("xtsc note Running in Fast Functional mode - Profiling/Cycle results will be incorrect!!!")
else
  xtsc.cmd("xtsc note Running in cycle-accurate mode")
end
xtsc.cmd("sc wait Host.core_exited_event")
xtsc.cmd("sc wait 1000")
--xtsc.cmd("xtsc xtsc_event_notify xtsc_command_prompt_event")
rc = xtsc.cmd("Host get_exit_code")
if rc == "0" then
  xtsc.cmd("xtsc note 0 exit code")
else
  xtsc.cmd("xtsc note exit code is " .. rc)
end
xtsc.cmd("xtsc note Host exited, now calling sc_stop")
xtsc.cmd("sc sc_stop")
