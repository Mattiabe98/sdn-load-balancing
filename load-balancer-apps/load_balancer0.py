from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import switches
import networkx as nx
import json
import logging
import struct
from webob import Response
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib.packet import arp, ipv4, tcp, udp, icmp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath
# from ryu.app.wsgi import WSGIApplication
import ryu.app.ofctl.api as api
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from ryu.lib import hub
from operator import attrgetter

MONITORING_INTERVAL = 5  # every MONITORING_INTERVAL seconds we get the measurements from the topology


class MyFirstApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyFirstApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.src_dict = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.lastNet = nx.DiGraph()
        self.capacity = []
        self.edges = []
        self.mac_to_dpid = {}
        self.port_to_mac = {}
        self.ip_to_mac = {}
        self.port_occupied = {}
        self.GLOBAL_VARIABLE = 0
        self.switches = []
        self.datapaths = {}
        self.load = {}
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        while True:
            self.create_chart()
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(MONITORING_INTERVAL)

    # function to retrieve the port of a link given the two endpoints (u and v) associated to the link
    def getPortNumber(self, u, v):
        # edge = self.net.edges[u, v]  # Get the edge between nodes u and v
        links_list = get_link(self.topology_api_app, u)
        for link in links_list:
            if link.dst.dpid == v:
                return link.src.port_no
        return None  # Return the port number if it exists, otherwise return None

    # function to retrieve the second enpoint node of a link given the first node and its port number identifying the link
    def getLinkDestNode(self, u, port):
        # node1 = get_switch(self.topology_api_app, u)
        links_list = get_link(self.topology_api_app, u)
        for link in links_list:
            # self.logger.info("The link %s has associated the source port %s (I'm searching for stat of port %s)", link, link.src.port_no, port)
            if link.src.port_no == port:
                return link.dst.dpid
        return None

    # function that, given an edge (node u and v) of the network, returns a flow (described as src, dst and in_port of the switch that needs to modify the rule) passing through that link to offload it
    def getFlowfromLink(self, u, v):
        return src, dst, in_port

    def getweight(self, u, v, dict):
        return self.net.edges[(u, v)]['weight']

    def _request_stats(self, datapath):
        # self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # ----------------------------------------------------------
    # Write the function: Add a flow in the switch flow table
    # ----------------------------------------------------------
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        ##############################################################################################
        # This section is needed to guarantee that each rule is installed in order.
        # Otherwise, there are problems in which a packet goes back to the controller because the
        # rule in the next switch has still to be implemented.
        # We send a barrier request that forces the switch to install it immediately before processing
        # another packet.
        # Fixed in OpenFlow 1.4 with BundleMsg
        msg = parser.OFPBarrierRequest(datapath)
        api.send_msg(self, msg, reply_cls=datapath.ofproto_parser.OFPBarrierReply, reply_multi=True)
        ##############################################################################################

    # Function to send an ARP message
    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        # If it is an ARP request
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        # If it is an ARP reply
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    #
    #
    # EVENT HANDLERS
    #
    #

    # --------------------------------------------------------------------
    # Write the function: Upon a switch feature reply, add the table miss
    # --------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath  # switch that sent the message
        ofproto = datapath.ofproto  # protocol used to interact with OpenFlow
        parser = datapath.ofproto_parser  # parser used to interact with OpenFlow

        # install the table-miss flow entry.
        match = parser.OFPMatch()  # match all the packets
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,  # send packets to controller
                                          ofproto.OFPCML_NO_BUFFER)]  # length of data to be sent
        self.add_flow(datapath, 0, match,
                      actions)  # adding a flow to current switch with priority 0, with match and actions previously defined
        self.logger.info("Table miss installed for switch: %s", datapath.id)

        # TOPOLOGY DISCOVERY------------------------------------------
        switch_list = get_switch(self.topology_api_app, None)
        self.switches = [switch.dp.id for switch in switch_list]
        if self.GLOBAL_VARIABLE == 0:
            for id_, s in enumerate(self.switches):
                for switch_port in range(1, len(switch_list[id_].ports)):
                    self.port_occupied.setdefault(s, {})
                    self.port_occupied[s][switch_port] = 0
        self.net.add_nodes_from(self.switches)
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no, 'weight': 0}) for link in links_list]
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no, 'weight': 0}) for link in links_list]
        self.net.add_edges_from(links)
        self.lastNet = self.net.copy()  # create a copy of the graph in order to store the last values of the bandwith and calculate the difference

    # ---------------------------------------------------
    # Write the function that handle a packet-in request
    # ---------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath  # switch that sends the packet_in
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)  # extract the packet
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]  # ethernet header of the packet received by controller
        dst = eth_pkt.dst  # MAC destination of the packet
        src = eth_pkt.src  # SRC destination of the packet
        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid,
                                    {})  # python dictionary for the switch dpid with an empty dictionary as its value if it does not already exist
        self.port_to_mac.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        self.mac_to_dpid[src] = dpid
        self.port_to_mac[dpid][in_port] = src

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore ipv6 packet
            return

        links_list = get_link(self.topology_api_app, None)
        links_ = [(link.dst.dpid, link.src.dpid, link.dst.port_no) for link in links_list]
        for l in links_:
            self.port_occupied[l[0]][l[2]] = 1

        # HANDLE ETHERNET FRAME ---------------------------

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if src not in self.net:
            # adding links between hosts and switch
            self.net.add_node(src)
            self.lastNet.add_node(src)

            self.net.add_edge(dpid, src, port=in_port, weight=0)
            self.lastNet.add_edge(dpid, src, port=in_port, weight=0)

            self.net.add_edge(src, dpid, port=1, weight=0)
            self.lastNet.add_edge(src, dpid, port=1, weight=0)
            # (avoid this part since this should not be part of the load balancer)
            # self.edges.setdefault(dpid, {})[src] = {'port': in_port, 'weight': 0}  #doing the same thing in the auxiliary dictionary (first node is the source and second is the dest of the edge)
            # self.edges.setdefault(src, {})[dpid] = {'port': 1, 'weight': 0}  #doing the same thing in the auxiliary dictionary

        if dst in self.net:
            path = nx.dijkstra_path(self.net, src, dst, weight=self.getweight)
            self.logger.info('path from %s to %s is %s. Message from switch %s', src, dst, path, dpid)
            # if dpid in path:
            next = path[path.index(dpid) + 1]
            out_port = self.net.edges[(dpid, next)]['port']
            # self.logger.info('path from %s to %s is %s. Message from switch %s is sent out to the port %s', src, dst, path, dpid, out_port)

        else:
            out_port = ofproto.OFPP_FLOOD

        # HANDLE ARP PACKETS--------------------------------------------

        if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
            arp_packet = pkt.get_protocol(arp.arp)
            arp_dst_ip = arp_packet.dst_ip
            arp_src_ip = arp_packet.src_ip
            # self.logger.info("It is an ARP packet")
            # If it is an ARP request
            if arp_packet.opcode == 1:
                # self.logger.info("It is an ARP request")
                if arp_dst_ip in self.ip_to_mac:
                    # self.logger.info("The address is inside the IP TO MAC table")
                    srcIp = arp_dst_ip
                    dstIp = arp_src_ip
                    srcMac = self.ip_to_mac[arp_dst_ip]
                    dstMac = src
                    outPort = in_port
                    opcode = 2
                    self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
                    # self.logger.info("packet in %s %s %s %s", srcMac, srcIp, dstMac, dstIp)
                else:
                    # self.logger.info("The address is NOT inside the IP TO MAC table")
                    srcIp = arp_src_ip
                    dstIp = arp_dst_ip
                    srcMac = src
                    dstMac = dst
                    # learn the new IP address
                    self.ip_to_mac.setdefault(srcIp, {})
                    self.ip_to_mac[srcIp] = srcMac
                    # Send and ARP request to all the switches
                    opcode = 1
                    for id_switch in self.switches:
                        # if id_switch != dpid_src:
                        datapath_dst = get_datapath(self, id_switch)
                        for po in range(1, len(self.port_occupied[id_switch]) + 1):
                            if self.port_occupied[id_switch][po] == 0:
                                outPort = po
                                if id_switch == dpid:
                                    if outPort != in_port:
                                        self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
                                else:
                                    self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)

            else:
                srcIp = arp_src_ip
                dstIp = arp_dst_ip
                srcMac = src
                dstMac = dst
                if arp_dst_ip in self.ip_to_mac:
                    # learn the new IP address
                    self.ip_to_mac.setdefault(srcIp, {})
                    self.ip_to_mac[srcIp] = srcMac
                    # Send and ARP reply to the switch
                opcode = 2
                outPort = self.mac_to_port[self.mac_to_dpid[dstMac]][dstMac]
                datapath_dst = get_datapath(self, self.mac_to_dpid[dstMac])
                self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)

        # HANDLE IP PACKETS-----------------------------------------------

        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip4_pkt:
            src_ip = ip4_pkt.src
            dst_ip = ip4_pkt.dst
            src_MAC = src
            dst_MAC = dst
            proto = str(ip4_pkt.proto)
            sport = "0"
            dport = "0"
            if proto == "6":  # TCP packet
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                sport = str(tcp_pkt.src_port)
                dport = str(tcp_pkt.dst_port)

            if proto == "17":  # UDP packet
                udp_pkt = pkt.get_protocol(udp.udp)
                sport = str(udp_pkt.src_port)
                dport = str(udp_pkt.dst_port)

            # construct action list.
            actions = [parser.OFPActionOutput(out_port)]
            # self.logger.info("actions: %s", actions)

            # install a flow to avoid packet_in next time.
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match,
                              actions)  # add flow in the switch with priority 1 matching the in_port and dest MAC

            # construct packet_out message and send it.
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)

    def create_chart(self):
        if self.load:
            loadKeys = list(self.load.keys())
            loadKeys.sort()
            self.load = {i: self.load[i] for i in loadKeys}
            self.logger.info(self.load)
            x = np.arange(len(self.load.keys()))
            plt.figure(figsize=(20,10))
            plt.bar(x, self.load.values())
            plt.xlabel("Switch:Port")
            plt.ylabel("Traffic")
            plt.xticks(x, self.load.keys())
            plt.savefig('MyFigure.png', dpi=300)

    # FLOW STATS
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        # self.logger.info('datapath'
        #                  'in-port  eth-dst             eth-src            '
        #                  'out-port packets  bytes')
        # self.logger.info('--------'
        #                  '-------- -----------------   -----------------  '
        #                  '-------- -------- --------')
        # for stat in sorted([flow for flow in body if flow.priority == 1],
        #                    key=lambda flow: (flow.match['in_port'],
        #                                      flow.match['eth_dst'])):
        #     self.logger.info('%8x %8x %17s %17s %8x %8d %8d',
        #                      ev.msg.datapath.id,
        #                      stat.match['in_port'], stat.match['eth_dst'], stat.match['eth_src'],
        #                      stat.instructions[0].actions[0].port,
        #                      stat.packet_count, stat.byte_count)

    # PORT STATS
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, [MAIN_DISPATCHER])
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath     port  '
                         'rx-pkts  rx-bytes      rx-error '
                         'tx-pkts  tx-bytes      tx-error')
        self.logger.info('-------- -------- '
                         '-------- ------------- -------- '
                         '-------- ------------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%8d %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
            # self.lastNet = self.net.copy()
            # load balancing only in the links between switches (port 1 of switches is always connected to an host)
            if stat.port_no != 1 & stat.port_no != 4294967294 & stat.tx_bytes > 0:  # 4294967294 is the port 'fffffffe' loopback interface of hosts (skip it)
                u = int(ev.msg.datapath.id)
                v = self.getLinkDestNode(u, stat.port_no)
                try:
                    self.net.edges[(u, v)]['weight'] = (stat.rx_bytes + stat.tx_bytes) - self.lastNet.edges[(u, v)][
                        'weight']
                    self.lastNet.edges[(u, v)]['weight'] = (stat.rx_bytes + stat.tx_bytes)

                    self.load[(str(ev.msg.datapath.id) + ":" + str(stat.port_no))] = self.net.edges[(u, v)]['weight']
                    if float(self.net.edges[(u, v)]['weight']) > 100000:
                        self.logger.info("Detected high traffic between switches %s and %s", u, v)

                except:
                    print()

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                # self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                # self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
