#!/bin/sh
# Run after projectw to add a fastpath port to dp0
# You will need to setup the tap device or physical interface
# Also update to point to the controllers both routeflow and rffastpath

ovs-vsctl add-port dp0 tap_fastpath
ovs-vsctl set-controller dp0 tcp:127.0.0.1:6653 tcp:127.0.0.1:6633

