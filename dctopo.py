from mininet.topo import Topo

class MyTopo(Topo):
    def __init__(self):
        super(MyTopo, self).__init__()

        k = 10
        pod = k
        # Number of core switches: (k/2)^2
        L1 = (pod // 2) ** 2
        # Number of aggregation switches: k * (k/2)
        L2 = (pod * pod) // 2
        # Number of edge switches (same as aggregation)
        L3 = L2

        # Lists for switches by layer
        core_switches = []
        agg_switches = []
        edge_switches = []

        # Counter for assigning switch DPIDs and names
        switch_counter = 1

        # Create core switches (s1, s2, ...)
        for i in range(L1):
            dpid = "{:016x}".format(switch_counter)
            sw = self.addSwitch("s{}".format(switch_counter), dpid=dpid)
            core_switches.append(sw)
            switch_counter += 1

        # Create aggregation switches
        for i in range(L2):
            dpid = "{:016x}".format(switch_counter)
            sw = self.addSwitch("s{}".format(switch_counter), dpid=dpid)
            agg_switches.append(sw)
            switch_counter += 1

        # Create edge switches
        for i in range(L3):
            dpid = "{:016x}".format(switch_counter)
            sw = self.addSwitch("s{}".format(switch_counter), dpid=dpid)
            edge_switches.append(sw)
            switch_counter += 1

        # Connect core to aggregation
        # Each core switch connects to aggregation switches
        # For core index i, starting index = i mod (k/2)
        for i in range(L1):
            c_sw = core_switches[i]
            start = i % (pod // 2)
            for j in range(pod):
                agg_index = start + j * (pod // 2)
                self.addLink(c_sw, agg_switches[agg_index], bw=10)

        # Connect aggregation to edge
        # Each aggregation switch connects to edge switches in the same pod
        for i in range(L2):
            group = i // (pod // 2)
            for j in range(pod // 2):
                edge_index = group * (pod // 2) + j
                self.addLink(agg_switches[i], edge_switches[edge_index], bw=10)

        # Attach hosts to edge switches (2 hosts per edge switch)
        host_counter = 1
        for sw in edge_switches:
            for _ in range(2):
                mac = "00:00:00:00:00:{:02x}".format(host_counter)
                host = self.addHost("h{}".format(host_counter), mac=mac)
                self.addLink(sw, host, bw=10)
                host_counter += 1

topos = {"mytopo": lambda: MyTopo()}

