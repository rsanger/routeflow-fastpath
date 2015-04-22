# routeflow-fastpath
A simple RYU controller intended for use with RouteFlow to reduce the number of packet-in and packet-out messages


- Setup
1. Create a link between the physical network switches and the the controller.
	* You can use a tap interface to tunnel between two machines see http://backreference.org/2010/03/26/tuntap-interface-tutorial/. Download this code and compile it you might want to add TCP_NODELAY to the sockets.
2. Once routeflow is running and has installed its rules add this port to dp0 and ensure the same occurs on the network switches
	* See patch-ovs.sh which shows how to patch these tap ports into dp0, the same applies for physical interfaces
	* Note if you network is mininet use Intf("tap_fastpath", node=s1)
4. Add both rffastpath.py as an additional controller to both dp0 and the network switches
	* See patch-ovs.sh which shows how to patch these tap ports into dp0, the same applies for physical interfaces
5. Update DP IDs and ports at the top of rffastpath to match your network
6. Run ryu-manager rffastpath.py
7. Done
