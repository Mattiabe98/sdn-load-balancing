"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.link import TCLink

bw = 100

class MyTopo( Topo ):
	"Simple topology example."

	def __init__( self ):
		"Create custom topo."

        # Initialize topology
		Topo.__init__( self )

        # Add hosts and switches
		h1 = self.addHost( 'h1' )
		h2 = self.addHost( 'h2' )
		h3 = self.addHost( 'h3' )
		h4 = self.addHost( 'h4' )
		h5 = self.addHost( 'h5' )
		h6 = self.addHost( 'h6' )
		h7 = self.addHost( 'h7' )
		h8 = self.addHost( 'h8' )
		h9 = self.addHost( 'h9' )
		s1 = self.addSwitch( 's1' )
		s2 = self.addSwitch( 's2' )
		s3 = self.addSwitch( 's3' )
		s4 = self.addSwitch( 's4' )
		s5 = self.addSwitch( 's5' )
		s6 = self.addSwitch( 's6' )
		s7 = self.addSwitch( 's7' )



        # Add links: bw in Mbps
		self.addLink(h1, s1, cls=TCLink, bw=bw)
		self.addLink(h2, s1, cls=TCLink, bw=bw)
		self.addLink(h3, s2, cls=TCLink, bw=bw)
		self.addLink(h4, s3, cls=TCLink, bw=bw)
		self.addLink(h5, s4, cls=TCLink, bw=bw)
		self.addLink(h6, s5, cls=TCLink, bw=bw)
		self.addLink(h7, s6, cls=TCLink, bw=bw)
		self.addLink(h8, s7, cls=TCLink, bw=bw)
		self.addLink(h9, s7, cls=TCLink, bw=bw)
		self.addLink(s1, s2, cls=TCLink, bw=bw)
		self.addLink(s1, s4, cls=TCLink, bw=bw)
		self.addLink(s2, s3, cls=TCLink, bw=bw)
		self.addLink(s3, s4, cls=TCLink, bw=bw)
		self.addLink(s3, s5, cls=TCLink, bw=bw)
		self.addLink(s3, s6, cls=TCLink, bw=bw)
		self.addLink(s4, s5, cls=TCLink, bw=bw)
		self.addLink(s4, s6, cls=TCLink, bw=bw)
		self.addLink(s4, s7, cls=TCLink, bw=bw)
		self.addLink(s5, s6, cls=TCLink, bw=bw)
		self.addLink(s5, s7, cls=TCLink, bw=bw)

topos = { 'mytopo': ( lambda: MyTopo() ) }
