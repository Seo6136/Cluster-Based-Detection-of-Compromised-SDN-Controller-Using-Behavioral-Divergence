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

        # Host and switch data structures
        self.host_ip_mapping = {}    # { host: ip }
        self.ip_to_host = {}         # { ip: host }
        self.host_to_switch = {}     # { host: switch }
        self.host_mac_mapping = {}   # { host: mac }

        self.forwarding_table = {}   # { switch: { dst_ip: [out_port1, out_port2, ...] } }
        self.forwarding_info = {}    # { (switch, host): (ip, mac, [out_ports]) }

        # Counters for PacketIn/PacketOut per switch (by DPID)
        self.switch_counters = {}    # { dpid: {"packet_in": int, "packet_out": int} }

        # Precompute topology, static MAC mapping, and forwarding table
        self._build_topology_and_hosts()
        self._load_static_mac_mapping()
        self._precompute_forwarding()
        self._save_forwarding_info()

        # Malicious behavior selection (choose 1–3 of dummy_flow, mirroring, silent_drop)
        self.malicious_types = {
            "dummy_flow": False,
            "mirroring": False,
            "silent_drop": False
        }
        num_malicious = random.randint(1, 3)
        selected_types = random.sample(list(self.malicious_types.keys()), num_malicious)
        for m_type in selected_types:
            self.malicious_types[m_type] = True
        self.logger.info("Selected malicious types: %s", 
                         [m for m, enabled in self.malicious_types.items() if enabled])

        switches = [n for n in self.topo.nodes if n.startswith('s')]

        # dummy_flow malicious behavior
        if self.malicious_types["dummy_flow"]:
            if switches:
                self.malicious_switch = random.choice(switches)
                self.logger.info("Malicious switch selected: %s", self.malicious_switch)
                distances = nx.shortest_path_length(self.topo, source=self.malicious_switch)
                max_dist = max(d for n, d in distances.items() if n.startswith('s'))
                threshold = int(max_dist * 0.4)
                self.malicious_neighbors = {
                    n for n, d in distances.items()
                    if n.startswith('s') and n != self.malicious_switch and d <= threshold
                }
                self.logger.info("Neighbor switches for dummy flows: %s", self.malicious_neighbors)
            else:
                self.malicious_switch = None
                self.malicious_neighbors = set()
        else:
            self.malicious_switch = None
            self.malicious_neighbors = set()

        # mirroring malicious behavior
        if self.malicious_types["mirroring"]:
            if switches:
                self.mirroring_switch = random.choice(switches)
                self.logger.info("Mirroring switch selected: %s", self.mirroring_switch)
            else:
                self.mirroring_switch = None
            hosts = list(self.host_ip_mapping.keys())
            if hosts:
                self.mirroring_host = random.choice(hosts)
                self.logger.info("Mirroring host selected: %s", self.mirroring_host)
            else:
                self.mirroring_host = None
        else:
            self.mirroring_switch = None
            self.mirroring_host = None

        # silent_drop malicious behavior
        if self.malicious_types["silent_drop"]:
            if switches:
                self.silent_drop_switch = random.choice(switches)
                self.logger.info("Silent-drop switch selected (20%% drop chance): %s", 
                                 self.silent_drop_switch)
            else:
                self.silent_drop_switch = None
        else:
            self.silent_drop_switch = None

        # If dummy_flow is enabled, install initial dummy flows after 10 seconds
        if self.malicious_types["dummy_flow"]:
            hub.spawn_after(10, self._install_initial_dummy_flows)

        # Start periodic thread for updating packet counters every 5 seconds
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

        self.logger.info("Generated host IP mapping: %s", self.host_ip_mapping)

    def _load_static_mac_mapping(self):
        if not os.path.exists('mac.txt'):
            self.logger.error("mac.txt not found.")
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

        self.logger.info("Loaded static MAC mapping: %s", self.host_mac_mapping)

    def _precompute_forwarding(self):
        self.logger.info("Starting precomputation of forwarding tables.")
        for sw in [n for n in self.topo.nodes if n.startswith('s')]:
            self.forwarding_table[sw] = {}
            for host, ip in self.host_ip_mapping.items():
                dst_sw = self.host_to_switch.get(host)
                if not dst_sw:
                    continue
                try:
                    out_ports = []
                    if sw == dst_sw:
                        try:
                            port = self._get_out_port(sw, host)
                            if port not in out_ports:
                                out_ports.append(port)
                        except Exception as e:
                            self.logger.error("Error: %s", e)
                    else:
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
            raise Exception(f"No port info: {src} -> {dst}")
        return int(edge_data['port'].replace('eth', ''))

    def _save_forwarding_info(self):
        try:
            with open('forwarding_info.txt', 'w') as f:
                for (sw, host), (ip, mac, out_ports) in self.forwarding_info.items():
                    ports_str = ",".join(map(str, out_ports))
                    f.write(f"{sw} {host} {ip} {mac} {ports_str}\n")
            self.logger.info("Saved forwarding_info.txt.")
        except Exception as e:
            self.logger.error("Failed to save forwarding_info.txt: %s", e)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

        dpid = datapath.id
        self.datapaths[dpid] = datapath
        self.switch_counters[dpid] = {"packet_in": 0, "packet_out": 0}

        self.logger.info("Switch registered: s%d", dpid)

    def _install_initial_dummy_flows(self):
        if not self.malicious_switch:
            return

        for neighbor in self.malicious_neighbors:
            neighbor_dpid = int(neighbor[1:])
            neighbor_dp = self.datapaths.get(neighbor_dpid)
            if not neighbor_dp:
                self.logger.warning("Failed initial dummy rule install: datapath not registered for %s", neighbor)
                continue
            dummy_match = neighbor_dp.ofproto_parser.OFPMatch(eth_type=0x0800, ip_dscp=63)
            dummy_inst = [neighbor_dp.ofproto_parser.OFPInstructionActions(
                neighbor_dp.ofproto.OFPIT_APPLY_ACTIONS, []
            )]
            dummy_mod = neighbor_dp.ofproto_parser.OFPFlowMod(
                datapath=neighbor_dp,
                priority=65535,
                match=dummy_match,
                instructions=dummy_inst,
                idle_timeout=60000,
                hard_timeout=60000,
                cookie=0xdeadbabe
            )
            neighbor_dp.send_msg(dummy_mod)
            self.logger.info("Installed high-priority dummy rule on %s: %s", neighbor, dummy_match)

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

        self.logger.debug("Ethernet: src=%s, dst=%s, type=0x%04x",
                          eth_pkt.src, eth_pkt.dst, eth_pkt.ethertype)

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.logger.info("Received ARP packet: opcode=%s, src_ip=%s, dst_ip=%s",
                             arp_pkt.opcode, arp_pkt.src_ip, arp_pkt.dst_ip)
            self._handle_arp(datapath, in_port, arp_pkt, eth_pkt)
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            self.logger.debug("Not an IPv4 packet")
            return

        if dpid in self.switch_counters:
            self.switch_counters[dpid]["packet_in"] += 1

        dst_ip = ip_pkt.dst
        src_ip = ip_pkt.src

        sw_name = f's{dpid}'

        # silent_drop: drop packets randomly with 20% chance on selected switch
        if (self.malicious_types["silent_drop"] and
            self.silent_drop_switch and
            sw_name == self.silent_drop_switch):
            if random.random() < 0.2:
                self.logger.info("Packet silently dropped: %s -> %s", src_ip, dst_ip)
                return

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        src_port = tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else 0)
        dst_port = tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else 0)

        params = get_policy_parameters(src_ip, dst_ip, ip_pkt.proto, src_port, dst_port)
        priority = params['priority']
        idle_timeout = params['idle_timeout']
        hard_timeout = params['hard_timeout']

        out_ports = self.forwarding_table.get(sw_name, {}).get(dst_ip)
        if not out_ports:
            self.logger.info("No forwarding info: %s -> %s", sw_name, dst_ip)
            return

        out_port = random.choice(out_ports)
        self.logger.info("IPv4 packet: %s -> %s, proto: %d, out_port: %d",
                         src_ip, dst_ip, ip_pkt.proto, out_port)

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
        output_count = 1

        # mirroring: add mirror action on selected switch
        if (self.malicious_types["mirroring"] and
            self.mirroring_switch and
            sw_name == self.mirroring_switch and
            self.mirroring_host):
            mirror_host_ip = self.host_ip_mapping[self.mirroring_host]
            mirror_host_mac = self.host_mac_mapping.get(self.mirroring_host, "unknown")
            mirror_out_ports = self.forwarding_table.get(sw_name, {}).get(mirror_host_ip)
            if mirror_out_ports:
                mirror_out_port = random.choice(mirror_out_ports)
                actions += [
                    parser.OFPActionSetField(eth_dst=mirror_host_mac),
                    parser.OFPActionSetField(ipv4_dst=mirror_host_ip),
                    parser.OFPActionOutput(mirror_out_port)
                ]
                self.logger.info("Added mirroring action: %s -> %s", dst_ip, mirror_host_ip)
                output_count = 2
            else:
                self.logger.warning("No mirroring path: %s -> host %s", sw_name, self.mirroring_host)

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
        self.logger.info(
            "Installed flow: %s -> %s (port %d, proto %d) [priority=%d, idle=%d, hard=%d]",
            sw_name, dst_ip, out_port, ip_pkt.proto, priority, idle_timeout, hard_timeout
        )

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
        if dpid in self.switch_counters:
            self.switch_counters[dpid]["packet_out"] += output_count

        # dummy_flow: install dummy flow on malicious switch for neighbor traffic
        if (self.malicious_types["dummy_flow"] and
            self.malicious_switch and
            sw_name in self.malicious_neighbors):
            dummy_match_fields = dict(match_fields)
            dummy_match_fields['ip_dscp'] = 63
            dummy_match = parser.OFPMatch(**dummy_match_fields)
            dummy_inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
            malicious_dpid = int(self.malicious_switch[1:])
            malicious_dp = self.datapaths.get(malicious_dpid)
            if malicious_dp:
                dummy_mod_mal = parser.OFPFlowMod(
                    datapath=malicious_dp,
                    priority=priority,
                    match=dummy_match,
                    instructions=dummy_inst,
                    idle_timeout=idle_timeout,
                    hard_timeout=hard_timeout,
                    cookie=0xdeadbeef
                )
                malicious_dp.send_msg(dummy_mod_mal)
                self.logger.info("Installed dummy rule on malicious switch %s: %s",
                                 self.malicious_switch, dummy_match)
            else:
                self.logger.warning("Datapath not registered for malicious switch %s", self.malicious_switch)

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
            self.logger.info("No static MAC for host %s", target_host)
            return

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
        self.logger.info("Sent static ARP reply: %s (%s) -> %s",
                         target_ip, target_mac, arp_pkt.src_ip)

    def _update_counters_loop(self):
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

