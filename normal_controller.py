from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, udp
from ryu.lib import hub
import networkx as nx
import os
import random

def get_policy_parameters(src_ip, dst_ip, protocol, src_port, dst_port):
    if protocol == 6:  # TCP
        return {'priority': 12, 'idle_timeout': 1200, 'hard_timeout': 3000}
    elif protocol == 17:  # UDP
        return {'priority': 10, 'idle_timeout': 1200, 'hard_timeout': 3000}
    elif protocol == 1:  # ICMP
        return {'priority': 10, 'idle_timeout': 1000, 'hard_timeout': 3000}

class StaticForwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StaticForwarding, self).__init__(*args, **kwargs)
        self.topo = nx.DiGraph()
        self.datapaths = {}

        # Host and switch mappings
        self.host_ip_mapping = {}    # { host: ip }
        self.ip_to_host = {}         # { ip: host }
        self.host_to_switch = {}     # { host: switch }
        self.host_mac_mapping = {}   # { host: mac }

        # forwarding_table: { switch: { dst_ip: [out_port1, out_port2, ...] } }
        self.forwarding_table = {}
        # forwarding_info: { (switch, host): (ip, mac, [out_ports]) }
        self.forwarding_info = {}

        # PacketIn/PacketOut counters per switch (by dpid)
        self.switch_counters = {}    # { dpid: {"packet_in": int, "packet_out": int} }

        # Build topology, load MAC mappings, precompute forwarding, and save info
        self._build_topology_and_hosts()
        self._load_static_mac_mapping()
        self._precompute_forwarding()
        self._save_forwarding_info()

        # Start thread to periodically update packet counters (every 5 seconds)
        self.monitor_thread = hub.spawn(self._update_counters_loop)

    def _build_topology_and_hosts(self):
        host_set = set()
        with open('nodes.txt', 'r') as f:
            nodes = f.read().split()
            for node in nodes:
                self.topo.add_node(node)
        with open('links.txt', 'r') as f:
            for line in f:
                if '<->' not in line:
                    continue
                left, right = line.split('<->')[0:2]
                a_node, a_port = left.split('-', 1)
                b_node, b_port = right.split('-', 1)
                a_port = a_port.split()[0]
                b_port = b_port.split()[0]
                self.topo.add_edge(a_node, b_node, port=a_port)
                self.topo.add_edge(b_node, a_node, port=b_port)
                if a_node.startswith('h') and b_node.startswith('s'):
                    self.host_to_switch[a_node] = b_node
                elif b_node.startswith('h') and a_node.startswith('s'):
                    self.host_to_switch[b_node] = a_node
                if a_node.startswith('h'):
                    host_set.add(a_node)
                if b_node.startswith('h'):
                    host_set.add(b_node)
        for i, host in enumerate(sorted(host_set, key=lambda h: int(h[1:]))):
            ip = f"10.0.0.{i+1}"
            self.host_ip_mapping[host] = ip
            self.ip_to_host[ip] = host

        self.logger.info("Auto host IP mapping: %s", self.host_ip_mapping)

    def _load_static_mac_mapping(self):
        if not os.path.exists('mac.txt'):
            self.logger.error("mac.txt file does not exist.")
            return

        with open('mac.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    host, mac = parts[0], parts[1]
                    self.host_mac_mapping[host] = mac

        self.logger.info("Static MAC mapping loaded: %s", self.host_mac_mapping)

    def _precompute_forwarding(self):
        self.logger.info("Starting precomputation of static forwarding table.")
        for sw in [n for n in self.topo.nodes if n.startswith('s')]:
            self.forwarding_table[sw] = {}
            for host, ip in self.host_ip_mapping.items():
                dst_sw = self.host_to_switch.get(host)
                if not dst_sw:
                    continue
                try:
                    out_ports = []
                    if sw == dst_sw:
                        # Switch and host are directly connected
                        try:
                            port = self._get_out_port(sw, host)
                            if port not in out_ports:
                                out_ports.append(port)
                        except Exception as e:
                            self.logger.error("Error: %s", e)
                    else:
                        # Compute paths between switches
                        paths = list(nx.all_shortest_paths(self.topo, source=sw, target=dst_sw))
                        for path in paths:
                            if len(path) > 1:
                                next_hop = path[1]
                                try:
                                    port = self._get_out_port(sw, next_hop)
                                    if port not in out_ports:
                                        out_ports.append(port)
                                except Exception as e:
                                    self.logger.error("Error: %s", e)
                    if out_ports:
                        self.forwarding_table[sw][ip] = out_ports
                        # Save forwarding info (ip, mac, ports)
                        self.forwarding_info[(sw, host)] = (
                            ip,
                            self.host_mac_mapping.get(host, "unknown"),
                            out_ports
                        )
                except nx.NetworkXNoPath:
                    self.logger.warning("No path: %s -> %s", sw, dst_sw)
                except Exception as e:
                    self.logger.error("Error: %s", e)
        self.logger.info("Precomputed forwarding table: %s", self.forwarding_table)

    def _get_out_port(self, src, dst):
        edge_data = self.topo.get_edge_data(src, dst)
        if not edge_data or 'port' not in edge_data:
            raise Exception("No port info: %s -> %s" % (src, dst))
        return int(edge_data['port'].replace('eth', ''))

    def _save_forwarding_info(self):
        try:
            with open('forwarding_info.txt', 'w') as f:
                for (sw, host), (ip, mac, out_ports) in self.forwarding_info.items():
                    ports_str = ",".join(map(str, out_ports))
                    f.write(f"{sw} {host} {ip} {mac} {ports_str}\n")
            self.logger.info("forwarding_info.txt saved successfully.")
        except Exception as e:
            self.logger.error("Failed to save forwarding_info.txt: %s", e)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Default flow: send all packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        dpid = datapath.id
        self.datapaths[dpid] = datapath

        # Initialize packet counters for this switch
        self.switch_counters[dpid] = {"packet_in": 0, "packet_out": 0}

        self.logger.info("Switch registered: s%d", dpid)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        in_port = msg.match.get('in_port', None)

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            self.logger.debug("No Ethernet header")
            return

        self.logger.debug("Ethernet: src=%s, dst=%s, type=0x%04x", eth_pkt.src, eth_pkt.dst, eth_pkt.ethertype)

        # Handle ARP packets separately
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.logger.info("Received ARP packet: opcode=%s, src_ip=%s, dst_ip=%s",
                             arp_pkt.opcode, arp_pkt.src_ip, arp_pkt.dst_ip)
            self._handle_arp(datapath, in_port, arp_pkt, eth_pkt)
            return

        # Process IPv4 packets (ICMP, TCP, UDP, etc.)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            self.logger.debug("Not an IPv4 packet")
            return

        # Increment PacketIn counter
        if dpid in self.switch_counters:
            self.switch_counters[dpid]["packet_in"] += 1

        dst_ip = ip_pkt.dst
        src_ip = ip_pkt.src

        # Extract TCP/UDP port info if present
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        src_port = 0
        dst_port = 0
        if tcp_pkt:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port

        # Determine policy parameters
        params = get_policy_parameters(src_ip, dst_ip, ip_pkt.proto, src_port, dst_port)
        priority = params['priority']
        idle_timeout = params['idle_timeout']
        hard_timeout = params['hard_timeout']

        sw_name = f's{dpid}'
        out_ports = self.forwarding_table.get(sw_name, {}).get(dst_ip)
        if not out_ports:
            self.logger.info("No forwarding info: %s -> %s", sw_name, dst_ip)
            return

        # Select a random output port if multiple available
        out_port = random.choice(out_ports)
        self.logger.info("IPv4 packet: %s -> %s, protocol: %d, out_port=%d",
                         src_ip, dst_ip, ip_pkt.proto, out_port)

        # Build match fields (including in_port)
        match_fields = {
            'in_port': in_port,
            'eth_type': 0x0800,
            'ipv4_src': src_ip,
            'ipv4_dst': dst_ip,
            'ip_proto': ip_pkt.proto
        }
        if tcp_pkt:
            match_fields['tcp_src'] = src_port
            match_fields['tcp_dst'] = dst_port
        elif udp_pkt:
            match_fields['udp_src'] = src_port
            match_fields['udp_dst'] = dst_port

        match = parser.OFPMatch(**match_fields)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)
        self.logger.info("Installed flow: %s -> %s (port %d, proto %d) [priority=%d, idle=%d, hard=%d]",
                         sw_name, dst_ip, out_port, ip_pkt.proto, priority, idle_timeout, hard_timeout)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

        # Increment PacketOut counter
        if dpid in self.switch_counters:
            self.switch_counters[dpid]["packet_out"] += 1

    def _handle_arp(self, datapath, in_port, arp_pkt, eth_pkt):
        if arp_pkt.opcode != arp.ARP_REQUEST:
            self.logger.debug("Not an ARP request (opcode=%s)", arp_pkt.opcode)
            return

        target_ip = arp_pkt.dst_ip
        if target_ip not in self.ip_to_host:
            self.logger.info("ARP request for unknown IP: %s", target_ip)
            return

        target_host = self.ip_to_host[target_ip]
        target_mac = self.host_mac_mapping.get(target_host)
        if not target_mac:
            self.logger.info("No static MAC mapping for host %s", target_host)
            return

        # Build and send static ARP reply
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=0x0806,
            dst=eth_pkt.src,
            src=target_mac))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=target_mac,
            src_ip=target_ip,
            dst_mac=eth_pkt.src,
            dst_ip=arp_pkt.src_ip))
        arp_reply.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=arp_reply.data
        )
        datapath.send_msg(out)
        self.logger.info("Sent static ARP reply: %s (%s) -> %s", target_ip, target_mac, arp_pkt.src_ip)

    def _update_counters_loop(self):
        """
        Every 5 seconds, write PacketIn/Out counters for each switch to a file.
        Format: "sX packet_in: Y, packet_out: Z, ratio: R"
        Ratio is packet_out/packet_in if packet_in > 0, otherwise "N/A".
        """
        while True:
            try:
                with open("packet_in_out.txt", "w") as f:
                    for dpid in sorted(self.switch_counters.keys()):
                        sw_name = f"s{dpid}"
                        pkt_in = self.switch_counters[dpid]["packet_in"]
                        pkt_out = self.switch_counters[dpid]["packet_out"]
                        ratio = f"{pkt_out / pkt_in:.2f}" if pkt_in > 0 else "N/A"
                        f.write(f"{sw_name} packet_in: {pkt_in}, packet_out: {pkt_out}, ratio: {ratio}\n")
            except Exception as e:
                self.logger.error("Failed to update packet_in_out.txt: %s", e)
            hub.sleep(5)

