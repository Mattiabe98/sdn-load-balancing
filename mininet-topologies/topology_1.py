"""
Custom topology example with 5 switches
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
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')

        # Add links: bw in Mbps

        #links host-switch
        self.addLink(h1, s1, cls=TCLink, bw=bw)
        self.addLink(h2, s1, cls=TCLink, bw=bw)
        self.addLink(h3, s2, cls=TCLink, bw=bw)
        self.addLink(h4, s2, cls=TCLink, bw=bw)
        self.addLink(h5, s4, cls=TCLink, bw=bw)
        self.addLink(h6, s4, cls=TCLink, bw=bw)
        self.addLink(h7, s5, cls=TCLink, bw=bw)
        self.addLink(h8, s5, cls=TCLink, bw=bw)
        #links switch-switch
        self.addLink(s1, s2, cls=TCLink, bw=bw)
        self.addLink(s1, s3, cls=TCLink, bw=bw)
        self.addLink(s1, s4, cls=TCLink, bw=bw)
        self.addLink(s2, s3, cls=TCLink, bw=bw)
        self.addLink(s2, s5, cls=TCLink, bw=bw)
        self.addLink(s3, s4, cls=TCLink, bw=bw)
        self.addLink(s3, s5, cls=TCLink, bw=bw)
        self.addLink(s4, s5, cls=TCLink, bw=bw)


topos = {'mytopo': (lambda: MyTopo())}
