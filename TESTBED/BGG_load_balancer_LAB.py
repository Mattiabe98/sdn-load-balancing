import pandas as pd
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_switch, get_link, get_host, get_all_host, get_all_link
import networkx as nx
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib.packet import arp, ipv4, tcp, udp, icmp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath
import ryu.app.ofctl.api as api
from ryu.lib import hub
from operator import attrgetter
import time
import math
import random
import sys

create_chart = False  # boolean variable to select if the controller has to create directly the chart here (if it is True) otherwise create files containing data and create the charts with another python script
LINK_UTILIZATION_THRESHOLD = 0.7  # threshold set at 70% of link utilization
MONITORING_INTERVAL = 2   # every MONITORING_INTERVAL seconds we get the measurements from the topology
CHART_INTERVAL = 10  # every CHART_INTERVAL seconds we store the new version of file/charts
REF_BW = (1 * 10 ** 8) / 8   # reference bandwidth in Bytes per second of link set in the mininet topologies (1Gbps)

class MyFirstApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyFirstApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.src_dict = {}
        self.topology_api_app = self
        self.mac_to_dpid = {}
        self.port_to_mac = {}
        self.ip_to_mac = {}
        self.port_occupied = {}
        self.GLOBAL_VARIABLE = 0
        self.monitor_thread = hub.spawn(self._monitor)
        self.allowed_macs = ["b8:27:eb:c2:10:5d", "b8:27:eb:d6:d4:c6", "b8:27:eb:83:1b:e2"]

        self.net = nx.DiGraph()   # graph representing the network
        self.lastNet = nx.DiGraph()   # graph to store in memory the last weight measurement

        self.start_time = None   # store the time instant when the application starts
        self.last_time = time.time()   # store the last time in which we save the data for the plots
        self.switches = []   # list of all the switches in the network
        self.hosts = []      # list of all hosts in the network
        self.links = []      # list of all links in the topology
        self.datapaths = {}   # list of datapath objects in the network
        self.flow_to_path = {}   # dictionary associating for each flow its current path through the network
        self.load = {}         # dictionary used for creating the chart over switch ports
        self.time_series = {}  # dictionary used for plotting the avg links' utilization over time

        self.sr_rx = 0  # number of stats reply received by the controller in order to manage the output in the console (every time a stats reply is received by any switch, it is incremented)
        self.counter_switch_configured = 0
        self.lb_on = False

    def _monitor(self):
        while True:
            if self.start_time is not None and time.time() - self.start_time > 5 and time.time() - self.last_time > CHART_INTERVAL:  # starting create the plot after 30 seconds and every CHART_INTERVAL
                self.last_time = time.time()
                self.create_avg_bw_util_chart()

            if self.start_time is not None and time.time() - self.start_time > 40 and self.lb_on is False:
                self.logger.info("LOAD BALANCER ON!")
                self.lb_on = True

            for dp in self.datapaths.values():
                if self.start_time is not None:   # start sending stats request only after having initialized the starting time instant (after all the switches have been configured)
                    self._request_stats(dp)
            hub.sleep(MONITORING_INTERVAL)

            if self.start_time is not None and time.time() - self.start_time > 70:
                # t2.join()  # wait for the thread about client script to terminate, SERVER SCRIPT NEVER STOPS
                self.logger.info("END OF SIMULATION!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                sys.exit()  # after 90 seconds we stop the simulation


    # function to understand if a node is a switch or not (end host)
    def isSwitch(self, u):
        if u is not None:   # end hosts are passed as None by the portStatsReply handler
            return True
        else:
            return False

    # function to retrieve the port of a link given the two endpoints (u and v) associated to the link
    def getPortNumber(self, u, v):
        links_list = get_link(self.topology_api_app, u)
        for link in links_list:
            if link.dst.dpid == v:
                return link.src.port_no
        return None  # Return the port number if it exists, otherwise return None

    # function to retrieve the second endpoint node of a link given the first node and its port number identifying the link
    def getLinkDestNode(self, u, port):
        #node1 = get_switch(self.topology_api_app, u)
        links_list = get_link(self.topology_api_app, u)
        for link in links_list:
            if link.src.port_no == port:
                return link.dst.dpid
        return None

    # function that, given an edge (node u and v) of the network, returns a flow (described as src, dst and out_port of the switch that needs to modify the rule) passing through that link to offload it
    # note that the self.net.edge attribute "flows" is a list with the following structure (for a single element) to define a flow: 'eth_src,eth_dst,out_port'
    def getFlowfromLink(self, u, v):
        random_index = random.randint(0, len(self.net.edges[(u, v)]["flows"]) - 1)   #selecting a random flows passing through the link to update its path
        flow = self.net.edges[(u, v)]["flows"][random_index]
        src = flow.split(",")[0]
        dst = flow.split(",")[1]
        out_port = flow.split(",")[2]   # output port of switch u
        return src, dst, out_port

    # function to pass as a parameter to dijkstra path (for the weights)
    def getweight(self, u, v, dict):
        return self.net.edges[(u, v)]['weight']

    # function to send request stats to the switches to retrieve network information
    def _request_stats(self, datapath):
        # self.logger.info('send stats request: %s', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # req = parser.OFPFlowStatsRequest(datapath)
        # datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)


    # ----------------------------------------------------------
    # Write the function: Add a flow in the switch flow table with the OFPBarrierReply
    # ----------------------------------------------------------
    def add_flow_barrier(self, datapath, priority, match, actions, buffer_id=None):
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
        # We send a barrier request that forces the switch to install it immediately before processing +another packet.
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

        # out_port = datapath.ofproto.OFPP_FLOOD
        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)
        self.logger.info("Sending ARP from " + str(srcIp) + ", " + str(srcMac) + "to: " + str(dstIp) + ", " + str(dstMac) + " TYPE: " + str(opcode))

    # function to send a FlowMod to update an existing flow with a new, load balanced output port
    def send_update_mod(self, datapath, src, dst, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        priority = 3  # increase the standard priority (1) for an update rules

        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        match = parser.OFPMatch(eth_src=src, eth_dst=dst)
        # req = parser.OFPFlowMod(datapath, cookie, cookie_mask,
        #                             table_id, ofproto.OFPFC_ADD,
        #                             idle_timeout, hard_timeout,
        #                             priority, buffer_id,
        #                             ofproto.OFPP_ANY, ofproto.OFPG_ANY,
        #                             ofproto.OFPFF_SEND_FLOW_REM,
        #                             match, inst)

        req = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, priority=priority, match=match, instructions=inst)
        datapath.send_msg(req)
        self.logger.info("____RULE ONE____" + str(datapath) + str(src) + str(dst) + str(out_port))

        msg = parser.OFPBarrierRequest(datapath)
        api.send_msg(self, msg, reply_cls=datapath.ofproto_parser.OFPBarrierReply, reply_multi=True)


    # function that creates the plot of average link bandwidth utilization over time
    # as Sebastian said we can plot the chart with the load balancer off and then on and observe the difference
    def create_avg_bw_util_chart(self):
        if self.time_series:
            # get from time_series data structure a pandas dataframe storing for each time instant the avg links' bw utilization
            avg_df = pd.DataFrame()
            avg_df = self.getAvgLinkBwUtilization(self.time_series)

            avg_df.to_csv('/home/ryu/net-aut-2022-2023/BGG/sdn-load-balancing/Measurements/lab/avg_utilization_lab.csv', index=False)


    #function used to retrieve a pandas dataframe containg for each time instant the average links bandwidth utilization given the self.time_series dictionary
    def getAvgLinkBwUtilization(self, ts):
        #create a DataFrame from the time_serie dictionary
        df = pd.DataFrame.from_dict(ts, orient='index')

        # group the rows by time instant and calculate the average weight for each group
        avg_df = df[df != 0].mean().reset_index()  # not include the links with no traffic (0 as weight)
        avg_df.columns = ["Time", "Average"]
        avg_df = avg_df.fillna(0)   # if all the links are zero, the average is not calculated and the cell is null. It is filled as 0
        avg_df = avg_df.sort_values(by="Time", ascending=True)

        return avg_df

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

        # install the table-miss flow entry only for allowed hosts
        for mac in self.allowed_macs: 

            match = parser.OFPMatch(eth_src=mac)  # match all the packets
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,  # send packets to controller
                                              ofproto.OFPCML_NO_BUFFER)]  # length of data to be sent
            self.add_flow_barrier(datapath, 1, match,
                          actions)  # adding a flow to current switch with priority 0, with match and actions previously defined
        self.logger.info("Table miss installed for switch: %s", datapath.id)

        match = parser.OFPMatch(eth_type=0x86dd)  # Discard all IPv6 packets
        actions = ""
        self.add_flow_barrier(datapath, 65535, match,
                              actions)
        match = parser.OFPMatch(eth_type=0x0800, eth_dst="ff:ff:ff:ff:ff:ff")  # Discard all IPv4 packets in broadcast (mDNS traffic)
        actions = ""
        self.add_flow_barrier(datapath, 65535, match,
                              actions)

        match = parser.OFPMatch()  # Discard all other unexpected packets, if no match found (priority 0)
        actions = ""
        self.add_flow_barrier(datapath, 0, match,
                              actions)

        # TOPOLOGY DISCOVERY------------------------------------------
        switch_list = get_switch(self.topology_api_app, None)
        #SWITCHES
        self.switches = [switch.dp.id for switch in switch_list]
        if self.GLOBAL_VARIABLE == 0:
            for id_, s in enumerate(self.switches):
                for switch_port in range(1, len(switch_list[id_].ports)):
                    self.port_occupied.setdefault(s, {})
                    self.port_occupied[s][switch_port] = 0
        self.net.add_nodes_from(self.switches)


        # LINKS
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no, 'weight': 0, 'flows': []}) for link in links_list]
        for link in links_list:
            #initialize for each edge (considered bidirectional) the weight as zero at time 0
            if link.src.dpid > link.dst.dpid:
                self.time_series[(link.src.dpid, link.dst.dpid)] = {0: 0}
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no, 'weight': 0, 'flows': []}) for link in links_list]
        self.net.add_edges_from(links)


        self.lastNet = self.net.copy()   # create a copy of the graph in order to store the last values of the bandwith and calculate the difference
        # self.logger.info("self.time_series is %s with length %s", self.time_series, len(self.time_series))

        self.counter_switch_configured += 1
        self.logger.info("Switch configured %s", self.counter_switch_configured)
        if self.counter_switch_configured == 6:
            self.logger.info("START SIMULATION!")
            self.logger.info("-----------------------------")
            self.logger.info(self.time_series)
            self.logger.info(self.net.edges)
            self.start_time = time.time()   # start the execution time when all the switches are configured

    # ---------------------------------------------------
    # Write the function that handle a packet-in request
    # ---------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        pkt = packet.Packet(msg.data)  # extract the packet
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]  # ethernet header of the packet received by controller

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore ipv6 packet
            return

        datapath = msg.datapath  # switch that sends the packet_in

        dst = eth_pkt.dst  # MAC destination of the packet
        src = eth_pkt.src  # SRC destination of the packet
        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        self.mac_to_port.setdefault(dpid, {})  # python dictionary for the switch dpid with an empty dictionary as its value if it does not already exist
        self.port_to_mac.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        self.mac_to_dpid[src] = dpid
        self.port_to_mac[dpid][in_port] = src

        links_list = get_link(self.topology_api_app, None)
        links_ = [(link.dst.dpid, link.src.dpid, link.dst.port_no) for link in links_list]
        for l in links_:
            self.port_occupied[l[0]][l[2]] = 1

        # HANDLE ETHERNET FRAME ---------------------------
        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if src not in self.net:
            # adding source host to the network
            self.net.add_node(src)
            self.lastNet.add_node(src)

            # adding links between hosts and switch
            self.net.add_edge(dpid, src, port=in_port, weight=0, flows=[])
            self.lastNet.add_edge(dpid, src, port=in_port, weight=0)

            self.net.add_edge(src, dpid, port=1, weight=0, flows=[])
            self.lastNet.add_edge(src, dpid, port=1, weight=0)

        if dst in self.net and dst != "ff:ff:ff:ff:ff:ff":

            self.logger.info("Searching a path from %s to %s", src, dst)
            if self.lb_on:
                path = nx.dijkstra_path(self.net, src, dst, weight=self.getweight)
            else:
                path = nx.dijkstra_path(self.net, src, dst)

            self.logger.info('path from %s to %s is %s. Message from switch %s', src, dst, path, dpid)
            next = path[path.index(dpid) + 1]
            out_port = self.net.edges[(dpid, next)]['port']

            self.flow_to_path[src + "," + dst] = path[1:-1]  # add the flow in the dictionary to keep track of the last path for that flow
        else:
            self.logger.info("Destination %s (packet from %s) not found in %s!!!", dst, src, self.net.nodes)

            out_port = ofproto.OFPP_FLOOD

            # HANDLE ARP PACKETS--------------------------------------------

            if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
                arp_packet = pkt.get_protocol(arp.arp)
                arp_dst_ip = arp_packet.dst_ip
                arp_src_ip = arp_packet.src_ip
                self.logger.info("It is an ARP packet")
                # If it is an ARP request
                if arp_packet.opcode == 1:
                    self.logger.info("It is an ARP request")
                    if arp_dst_ip in self.ip_to_mac:
                        self.logger.info("The address is inside the IP TO MAC table")
                        srcIp = arp_dst_ip
                        dstIp = arp_src_ip
                        srcMac = self.ip_to_mac[arp_dst_ip]
                        dstMac = src
                        outPort = in_port
                        opcode = 2
                        self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
                        self.logger.info("packet in %s %s %s %s", srcMac, srcIp, dstMac, dstIp)
                    else:
                        self.logger.info("The address is NOT inside the IP TO MAC table")
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
                    self.logger.info("ARP REPLY!!!!!!!!!!!!!!!!!!!!!")
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

            # install a flow to avoid packet_in next time.
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_dst=dst, eth_src=src)
                self.add_flow_barrier(datapath, 2, match,
                              actions)  # add flow in the switch with priority 1 matching the in_port and dest MAC

            flow_el = src + "," + dst + "," + str(out_port)  # defining the element of list flows for the edges

            if dst != "ff:ff:ff:ff:ff:ff" and dst in self.net:
                if flow_el not in self.net.edges[(dpid, next)]["flows"]:  # check to avoid duplicates
                    # insert the flow inside the networkx edge in order to keep track which flows pass through the graph edges
                    self.net.edges[(dpid, next)]["flows"].append(flow_el)

            # construct packet_out message and send it.
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)


    # ------------------- PORT STATS REPLY -----------------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, [MAIN_DISPATCHER])
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        # self.logger.info('datapath     port  '
        #                  'rx-pkts  rx-bytes      rx-error '
        #                  'tx-pkts  tx-bytes      tx-error')
        # self.logger.info('-------- -------- '
        #                  '-------- ------------- -------- '
        #                  '-------- ------------- --------')
        self.sr_rx += 1
        for stat in sorted(body, key=attrgetter('port_no')):
            #in order to print the measurement every show_interval seconds
            dp = ev.msg.datapath
            # self.logger.info('%8d %8x %8d %8d %8d %8d %8d %8d',
            #              dp.id, stat.port_no,
            #              stat.rx_packets, stat.rx_bytes, stat.rx_errors,
            #              stat.tx_packets, stat.tx_bytes, stat.tx_errors)

            # load balancing only in the links between switches (port 1 of switches is always connected to an host)
            if stat.port_no != 1 & stat.port_no != 4294967294 & stat.tx_bytes > 0:    # 4294967294 is the port 'fffffffe' loopback interface of hosts (skip it)
                u = dp.id
                v = self.getLinkDestNode(u, stat.port_no)

                # check if the two nodes are both switches, otherwise we are not interested in that link
                if self.isSwitch(u) and self.isSwitch(v):
                    # the weights will be the percentage of bandwidth used in the last monitoring interval
                    # (current bandwidth calculated as current (total bytes - last measurement)/MONITORING_INTERVAL = average Bytes per second in the last interval
                    if self.sr_rx <= 6:
                        self.lastNet.edges[(u, v)]['weight'] = stat.rx_bytes + stat.tx_bytes    # when we start the simulation we need to align the lastnet to the current value of traffic
                    self.net.edges[(u, v)]['weight'] = (((stat.rx_bytes + stat.tx_bytes) - self.lastNet.edges[(u, v)]['weight']) / MONITORING_INTERVAL) / REF_BW
                    self.lastNet.edges[(u, v)]['weight'] = stat.rx_bytes + stat.tx_bytes    # update the lastNet values
                    self.load[(str(dp.id) + ":" + str(stat.port_no))] = self.net.edges[(u, v)]['weight']

                    # self.logger.info(self.net.edges[(u, v)]['weight'])
                    if u > v:
                        if self.net.edges[(u, v)]['weight'] > 10**-9:
                            # self.time_series[(u, v)][int(time.time() - self.start_time)] = round(self.net.edges[(u, v)]["weight"], 3)
                            self.time_series[(u, v)][math.ceil(self.sr_rx/len(self.datapaths)) * MONITORING_INTERVAL] = round(self.net.edges[(u, v)]["weight"], 3)
                        else:
                            # self.time_series[(u, v)][int(time.time() - self.start_time)] = 0
                            self.time_series[(u, v)][math.ceil(self.sr_rx/len(self.datapaths)) * MONITORING_INTERVAL] = 0

                    if float(self.net.edges[(u, v)]['weight']) > LINK_UTILIZATION_THRESHOLD and self.lb_on:
                        self.logger.info("Detected high traffic between switches %s and %s with weight %s", u, v, self.net.edges[(u, v)]['weight'])
                        ######################################
                        # when traffic goes above a certain threshold on the bandwidth of a certain link, we update switches' flow table

                        src, dst, out_port = self.getFlowfromLink(u, v)  # retrieve flow information to update its path through the network

                        path = nx.dijkstra_path(self.net, src, dst, weight=self.getweight)  # calculating new path for this flow by passing the weight

                        self.flow_to_path[src + "," + dst] = path[1:-1]  # updating the path in the data structure associating flows to their path (removing first and last element since we don't need hosts)

                        # ADD NEW FLOW RULE (FOR THE NEW PATH)
                        path.reverse()
                        for sw in path[1:-1]:  # skip the first and last node in the path since they are the two end-device hosts
                            switch_obj = get_datapath(self, sw)
                            self.logger.info("Switch %s in path: %s", sw, path)
                            next = path[path.index(sw) - 1]
                            out_port = self.net.edges[(sw, next)]['port']
                            self.send_update_mod(switch_obj, src, dst, out_port)

                            flow_el = src + "," + dst + "," + str(out_port)  # defining the element of list flows for the edges
                            if flow_el not in self.net.edges[(sw, next)]["flows"]:
                                self.net.edges[(sw, next)]["flows"].append(flow_el)
                            self.logger.info("New flow path added in all switches!")

        if self.sr_rx % len(self.datapaths) == 0:
            #self.logger.info("Edge %s weight: %s", nx.get_edge_attributes(self.net, 'weight'))
            for edge in self.net.edges:
                edge_weight = self.net.edges[(edge[0], edge[1])]['weight']
                if edge_weight > 0.1:
                    self.logger.info("edge %s: %s", edge, edge_weight)

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
