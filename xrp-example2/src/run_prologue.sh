#!/bin/bash

function on_exit
{
  if kill -0 ${pids[0]} > /dev/null 2>&1; then
    kill -9 ${pids[0]}
  fi
  if kill -0 ${pids[1]} > /dev/null 2>&1; then
    kill -9 ${pids[1]}
  fi
  rm -f /dev/shm/SharedRAM_L
}

trap on_exit EXIT
trap on_exit INT

