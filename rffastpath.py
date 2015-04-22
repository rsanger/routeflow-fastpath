#!/usr/local/bin/ryu-manager

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3, ether
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu import cfg

class FastPath(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {
		'dpset': dpset.DPSet,
	}

	""" The controller id """
	dp0_dpid = 8243406406160905843 #7266767372667673
	""" The port connecting to the network """
	dp0_portid = 0x3

	""" The device connecting to the controller """
	net_dpid = 0x0000000000000001
	""" The port connecting to the controller """
	net_portid = 0x3

	""" This is a dict of dicts mapping dp_id -> port_id -> label  """
	net_mapping = {}

	""" Pushes and pops the meta label """
	labeller = None
	
	""" Our Special Cookie """
	cookie = 0xCA75

	def __init__(self, *args, **kwargs):
		super(FastPath, self).__init__(*args, **kwargs)
		self.dpset = kwargs['dpset']
#		self.labeller = MetaVLAN()
		self.labeller = MetaMPLS()

	""" ~~~~~ A collection of random nice print functions which print out ryu/OF structures ~~~~ """
	def print_switch_features(self, msg):

		print ('OFPSwitchFeatures received: '
			'datapath_id=0x%016x n_buffers=%d '
			'n_tables=%d auxiliary_id=%d '
			'capabilities=0x%08x') % (
			msg.datapath_id, msg.n_buffers, msg.n_tables,
			msg.auxiliary_id, msg.capabilities)

		print "!!!!Ports: %s" % (self.dpset.get_all())

	def print_rule(self, stat):
			print ('cookie=0x%1x,'
				' duration=%f,'
				' table=%s,'
				' n_packets=%d,'
				' n_bytes=%d,'
				' priority=%d '
				'idle_timeout=%d hard_timeout=%d flags=0x%04x '
				'match=%s instructions=%s' %
				(stat.cookie,
				stat.duration_sec + stat.duration_nsec * 1e-9,
				stat.table_id,
				stat.packet_count,
				stat.byte_count,
				stat.priority,
				stat.idle_timeout, stat.hard_timeout, stat.flags,
				stat.match, stat.instructions))
	def print_port(self, p):
			print ('port_no=%d hw_addr=%s name=%s config=0x%08x '
	                     'state=0x%08x curr=0x%08x advertised=0x%08x '
        	             'supported=0x%08x peer=0x%08x curr_speed=%d '
                	     'max_speed=%d' %
	                     (p.port_no, p.hw_addr,
        	              p.name, p.config,
                	      p.state, p.curr, p.advertised,
	                      p.supported, p.peer, p.curr_speed,
        	              p.max_speed))

	def combine_match(self, parser, match1, match2):
		"""
		Turns out matches are hard to work with, one does not simply add to one
		"""
		new_dict = {}
		for k, v in match1.iteritems():
				new_dict[k] = v
		for k, v in match2.iteritems():
				new_dict[k] = v
		return parser.OFPMatch(**new_dict)
		
	def request_controller_rules(self, datapath):
		print "Asking for rules datapath %s" % (datapath)

		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		
		cookie = cookie_mask = 0
		match = ofp_parser.OFPMatch()
		req = ofp_parser.OFPFlowStatsRequest(datapath, 0, ofp.OFPTT_ALL, ofp.OFPP_CONTROLLER 
#ofp.OFPP_ANY
			, ofp.OFPG_ANY, cookie, cookie_mask, match)

		datapath.send_msg(req)
	
	"""
	Clear all rules with our special cookie
	"""
	def clear_rules(self, datapath, cookie=None):
		if cookie == None:
			cookie = self.cookie
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch()
		mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, cookie_mask=0xFFFFFFFFFFFFFFFF,
			command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
			out_group=ofproto.OFPG_ANY, match=match, instructions=[], table_id=ofproto.OFPTT_ALL)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		msg = ev.msg

#		self.clear_rules(msg.datapath)
		self.print_switch_features(msg)
#		self.list_all_ports(msg.datapath)
#		self.list_all_rules(msg.datapath)

		
	def add_flow(self, datapath, match, actions, priority, cookie=None, table_id=0, inst=None):
		if cookie is None:
			cookie = self.cookie;
		if inst is None:
			inst = []
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		inst += [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		
		mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, priority=priority,
				command=ofproto.OFPFC_ADD, match=match, instructions=inst, table_id=table_id)
		print "\nAdding flow datapath=%s cookie=%d priority=%d %s %s\n" % (datapath, cookie, priority, match, inst)
		datapath.send_msg(mod)


	def add_default_rules(self):

		print "Current Associations:"
		for a, b in self.net_mapping.items():
			print "\t dpid: %d" % (a)
			for c, d in b.items():
				print "\t\t DPIDPort: %d -> label %d" % (c, d)
		
		""" Add rules to the port on the network """
		if self.net_dpid in self.net_mapping:
			net_dp = self.dpset.get(self.net_dpid)
			parser = net_dp.ofproto_parser
			for a, b in self.net_mapping[self.net_dpid].items():
				if b != self.labeller.bad_label():
					match = parser.OFPMatch(in_port=self.net_portid, **self.labeller.ofmatch_meta(parser, self.labeller.in2out(b)))
					actions = self.labeller.ofaction_pop_meta(parser)
					actions += [parser.OFPActionOutput(a)]
					self.add_flow(net_dp, match, actions, 32805)

		""" Add rules to the port on the dp0 """
		if self.dp0_dpid in self.net_mapping and self.net_dpid in self.net_mapping:
			dp0_dp = self.dpset.get(self.dp0_dpid)
			parser = net_dp.ofproto_parser
			for a, b in self.net_mapping[self.net_dpid].items():
				if b != self.labeller.bad_label():
					print "Adding rules to host controller"
					""" A rule to capture net -> controller """
					match = parser.OFPMatch(in_port=self.dp0_portid, **self.labeller.ofmatch_meta(parser, b))
					actions = self.labeller.ofaction_pop_meta(parser)
					actions += [parser.OFPActionOutput(a)]
					self.add_flow(dp0_dp, match, actions, 32805)

					""" A rule to capture controller -> net path """
					match = dp0_dp.ofproto_parser.OFPMatch(in_port=a)
					actions = self.labeller.ofaction_push_meta(parser, self.labeller.in2out(b))
                                        actions.append(parser.OFPActionOutput(self.dp0_portid))
                                        self.add_flow(dp0_dp, match, actions, 32805)


	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def flow_stats_reply_handler(self, ev):
		print 'FlowStats:\n'
		
#		self.rewrite_controller_rules(ev)
		self.rewrite_controller_rules_table(ev)

	def rewrite_controller_rules(self, ev):
		parser = ev.msg.datapath.ofproto_parser
		for stat in ev.msg.body:
			
			# TODO check this action is actually only output to the controller

#			For now assume every PKT IN rule is from all ports ;-()
			if self.net_dpid in self.net_mapping:
				for port, label in self.net_mapping[self.net_dpid].items():
					if (label != self.labeller.bad_label()):
						match = self.combine_match(parser, stat.match, {'in_port': port})
						action = self.labeller.ofaction_push_meta(parser, label)
						action += [parser.OFPActionOutput(self.net_portid)]
						self.add_flow(ev.msg.datapath, match, action, stat.priority+1)


	def rewrite_controller_rules_table(self, ev):
		parser = ev.msg.datapath.ofproto_parser

		# Make our table 2 which simply tags all packets with a VLAN related to it's port and fires them towards the controller
		if self.net_dpid in self.net_mapping:
			for port, label in self.net_mapping[self.net_dpid].items():
				if (label != self.labeller.bad_label()):
					match = parser.OFPMatch(in_port=port)
					action = self.labeller.ofaction_push_meta(parser, label)
					action += [parser.OFPActionOutput(self.net_portid)]
					self.add_flow(ev.msg.datapath, match, action, 3600, table_id=2)

		# For every rule targeting the controller add a rule at higher priority to send the packet to table 2 instead of the controller
		for stat in ev.msg.body:
			match = stat.match
			inst = [parser.OFPInstructionGotoTable(2)]
			action = []
			self.add_flow(ev.msg.datapath, match, action, stat.priority+1, inst=inst)

#		self.add_default_rules()

	def map_ports(self, dpid):
		print "Adding DPID %d" % (dpid)

		if dpid not in self.net_mapping:
			self.net_mapping[dpid] = {}
		dp = self.net_mapping[dpid]
		for port in self.dpset.get_ports(dpid):
			if ((port not in dp) and (port.port_no < self.dpset.get(dpid).ofproto.OFPP_MAX)
				and not (port.port_no == self.net_portid and dpid == self.net_dpid)
				and not (dpid == self.dp0_dpid)):
				dp[port.port_no] = self.labeller.allocate_label()
			else:
				dp[port.port_no] = self.labeller.bad_label()


	@set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
	def handle_datapath(self, ev):
		dp = ev.dp
		ofproto = dp.ofproto
		parser = dp.ofproto_parser

		self.clear_rules(dp)
		
		self.map_ports(dp.id)

		if (self.dp0_dpid in self.net_mapping and self.net_dpid in self.net_mapping):
			self.add_default_rules()

		if (dp.id == self.net_dpid):
			self.request_controller_rules(dp)

class MetaLabel:
	"""
	An abstract class see MetaVLAN and MetaMPLS for an implementation of this!!
	Adds the port as meta data to an OpenFlow action and assigns labels etc.
	"""

	def ofaction_push_meta(self, parser, label, action=None):
		"""
			Creates an OF action, or appends to an existing action the port label
		"""
		raise NotImplementedError("Should have implemented this" )

	def ofaction_pop_meta(self, parser, action=None):
		"""
			Removes the meta label from a port
		"""
		raise NotImplementedError("Should have implemented this" )

	def ofmatch_meta(self, parser, label, match=None):
		"""
			Adds a match action for a given label
		"""
		raise NotImplementedError("Should have implemented this" )

	def allocate_label(self):
		""" 
		Allocates a label for a new port - this returns PKTIN label
		PKTIN labels are those used by packets received on the network heading for
		the controller. Packet outs are those on return.
		"""
		raise NotImplementedError("Should have implemented this" )
	
	def bad_label(self):
		""" Returns a non existant label, indicating unassigned """
		return -1

	def in2out(self, label):
		""" Converts a PKTIN label to a path label to a PKTOUT label """
		""" We don't really need this as we can determine direction from the port """
		raise NotImplementedError("Should have implemented this" )
	
	def out2in(self, label):
		""" Converts a PKTOUT label to a PKTIN label """
		raise NotImplementedError("Should have implemented this" )

class MetaVLAN(MetaLabel):
	label = 1

	def ofaction_push_meta(self, parser, label, action=None):
		if action == None:
			action = []
		action += [parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
			   parser.OFPActionSetField(vlan_vid=(label|ofproto_v1_3.OFPVID_PRESENT))]
		return action

	def ofaction_pop_meta(self, parser, action=None):
		if action == None:
			action = []
		action.append(parser.OFPActionPopVlan())
		return action

	def ofmatch_meta(self, parser, label, match=None):
		if match == None:
			match = {}
		match['vlan_vid'] = label|ofproto_v1_3.OFPVID_PRESENT
		return match

	def allocate_label(self):
		ret = self.label
		self.label += 1
		if ret >= (1<<11):
			raise OverflowError("We've run out of VLAN labels for ports")
		return ret

	def in2out(self, label):
		return label
#		return label | (1<<11)
	
	def out2in(self, label):
		if label == -1:
			return -1
		return label & ~(1<<11)


#		OVS MPLS is buggy, particularly in older versions
#		http://tocai.dia.uniroma3.it/compunet-wiki/index.php?title=Bugs_and_limitations_in_OpenFlow_tools&oldid=830
#		For now just use VLANS
class MetaMPLS(MetaLabel):
	label = 1

	""" Why? I do not know, but this does not work!! """
	def ofaction_push_meta(self, parser, label, action=None, tc=0, BoS=1, ttl=10):
		if action == None:
			action = []
		action.append(parser.OFPActionPushMpls())
		action.append(parser.OFPActionSetField(mpls_label=label))
#		action.append(parser.OFPActionSetField(mpls_tc=tc))
# Setting BoS is not supported by OVS 
#		action.append(parser.OFPActionSetField(mpls_bos=BoS))
#		action.append(parser.OFPActionSetMplsTtl(ttl))
		return action

	def ofaction_pop_meta(self, parser, action=None):
		if action == None:
			action = []
		action.append(parser.OFPActionPopMpls())
		return action

	def ofmatch_meta(self, parser, label, match=None):
		if match == None:
			match = {}
		match['mpls_label'] = label
		return match

	def allocate_label(self):
		ret = self.label
		self.label += 1
		if ret >= (1<<18):
			raise OverflowError("We've run out of MPLS labels for ports")
		return ret

	def in2out(self, label):
		return label | (1<<18)
	
	def out2in(self, label):
		if label == -1:
			return -1
		return label & ~(1<<18)
