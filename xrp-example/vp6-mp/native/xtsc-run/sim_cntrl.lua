xtsc.cmd("sc wait Host.core_exited_event")
xtsc.cmd("sc wait 1000")
rc = xtsc.cmd("Host get_exit_code")
if rc == "0" then
 xtsc.cmd("xtsc note 0 exit code")
else
 xtsc.cmd("xtsc note exit code is " .. rc)
end
xtsc.cmd("xtsc note Host exited, now calling sc_stop")
xtsc.cmd("sc sc_stop")
