#!/bin/bash

valgrind --vgdb=yes --vgdb-error=0 /usr/cypherlib/test &
sleep 1s
gdb /usr/cypherlib/test
