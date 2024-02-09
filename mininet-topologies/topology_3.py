"""
Custom topology example with 10 switches
"""

from mininet.topo import Topo
from mininet.link import TCLink

bw = 100

class MyTopo(Topo):
    "Simple topology example."

    def __init__(self):
        "Create custom topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')
        h9 = self.addHost('h9')
        h10 = self.addHost('h10')
        h11 = self.addHost('h11')
        h12 = self.addHost('h12')
        h13 = self.addHost('h13')
        h14 = self.addHost('h14')
        h15 = self.addHost('h15')
        h16 = self.addHost('h16')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        s8 = self.addSwitch('s8')
        s9 = self.addSwitch('s9')
        s10 = self.addSwitch('s10')

        # Add links: bw in Mbps

        #links host-switch
        self.addLink(h1, s1, cls=TCLink, bw=bw)
        self.addLink(h2, s1, cls=TCLink, bw=bw)
        self.addLink(h3, s2, cls=TCLink, bw=bw)
        self.addLink(h4, s2, cls=TCLink, bw=bw)
        self.addLink(h5, s3, cls=TCLink, bw=bw)
        self.addLink(h6, s3, cls=TCLink, bw=bw)
        self.addLink(h7, s4, cls=TCLink, bw=bw)
        self.addLink(h8, s5, cls=TCLink, bw=bw)
        self.addLink(h9, s6, cls=TCLink, bw=bw)
        self.addLink(h10,s7, cls=TCLink, bw=bw)
        self.addLink(h11,s8, cls=TCLink, bw=bw)
        self.addLink(h12,s8, cls=TCLink, bw=bw)
        self.addLink(h13,s9, cls=TCLink, bw=bw)
        self.addLink(h14,s9, cls=TCLink, bw=bw)
        self.addLink(h15,s10, cls=TCLink, bw=bw)
        self.addLink(h16,s10, cls=TCLink, bw=bw)

        #links switch-switch
        self.addLink(s1, s2, cls=TCLink, bw=bw)
        self.addLink(s1, s4, cls=TCLink, bw=bw)
        self.addLink(s1, s6, cls=TCLink, bw=bw)
        self.addLink(s2, s5, cls=TCLink, bw=bw)
        self.addLink(s2, s7, cls=TCLink, bw=bw)
        self.addLink(s3, s4, cls=TCLink, bw=bw)
        self.addLink(s3, s6, cls=TCLink, bw=bw)
        self.addLink(s3, s7, cls=TCLink, bw=bw)
        self.addLink(s4, s7, cls=TCLink, bw=bw)
        self.addLink(s4, s8, cls=TCLink, bw=bw)
        self.addLink(s5, s6, cls=TCLink, bw=bw)
        self.addLink(s5, s9, cls=TCLink, bw=bw)
        self.addLink(s6, s8, cls=TCLink, bw=bw)
        self.addLink(s6, s10, cls=TCLink, bw=bw)
        self.addLink(s7, s9, cls=TCLink, bw=bw)
        self.addLink(s7, s10, cls=TCLink, bw=bw)
        self.addLink(s9, s10, cls=TCLink, bw=bw)


topos = {'mytopo': (lambda: MyTopo())}
