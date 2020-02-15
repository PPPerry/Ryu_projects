#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   controller=None,
                   ipBase='192.168.0.0/8')
    
    ## specify clearly to use a remote controller instead of the default one 
    c=RemoteController('c','0.0.0.0',6633)
    net.addController(c)

    info( '*** Add switches\n')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s11 = net.addSwitch('s11', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s8 = net.addSwitch('s8', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s6 = net.addSwitch('s6', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s7 = net.addSwitch('s7', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s10 = net.addSwitch('s10', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s9 = net.addSwitch('s9', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s12 = net.addSwitch('s12', cls=OVSKernelSwitch,protocols=['OpenFlow13'])
    s13 = net.addSwitch('s13', cls=OVSKernelSwitch,protocols=['OpenFlow13'])

    info( '*** Add hosts\n')
    h3 = net.addHost('h3', cls=Host, ip='192.168.0.3', defaultRoute=None,mac='00:00:00:00:00:03')
    h10 = net.addHost('h10', cls=Host, ip='192.168.0.10', defaultRoute=None,mac='00:00:00:00:00:10')
    h2 = net.addHost('h2', cls=Host, ip='192.168.0.2', defaultRoute=None,mac='00:00:00:00:00:02')
    h5 = net.addHost('h5', cls=Host, ip='192.168.0.5', defaultRoute=None,mac='00:00:00:00:00:05')
    h1 = net.addHost('h1', cls=Host, ip='192.168.0.1', defaultRoute=None,mac='00:00:00:00:00:01')
    h11 = net.addHost('h11', cls=Host, ip='192.168.0.11', defaultRoute=None,mac='00:00:00:00:00:11')
    h6 = net.addHost('h6', cls=Host, ip='192.168.0.6', defaultRoute=None,mac='00:00:00:00:00:06')
    h4 = net.addHost('h4', cls=Host, ip='192.168.0.4', defaultRoute=None,mac='00:00:00:00:00:04')
    h7 = net.addHost('h7', cls=Host, ip='192.168.0.7', defaultRoute=None,mac='00:00:00:00:00:07')
    h13 = net.addHost('h13', cls=Host, ip='192.168.0.255', defaultRoute=None,mac='00:00:00:00:00:ff')
    h9 = net.addHost('h9', cls=Host, ip='192.168.0.9', defaultRoute=None,mac='00:00:00:00:00:09')
    h12 = net.addHost('h12', cls=Host, ip='192.168.0.12', defaultRoute=None,mac='00:00:00:00:00:12')
    h8 = net.addHost('h8', cls=Host, ip='192.168.0.8', defaultRoute=None,mac='00:00:00:00:00:08')

    info( '*** Add links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s2)
    net.addLink(h3, s3)
    net.addLink(h4, s4)
    net.addLink(h5, s5)
    net.addLink(h6, s6)
    net.addLink(h7, s7)
    net.addLink(h8, s8)
    net.addLink(h9, s9)
    net.addLink(h10, s10)
    net.addLink(h11, s11)
    net.addLink(h12, s12)
    net.addLink(h13, s13)
    net.addLink(s2, s1)
    net.addLink(s2, s3)
    net.addLink(s3, s4)
    net.addLink(s2, s5)
    net.addLink(s5, s7)
    net.addLink(s5, s6)
    net.addLink(s5, s8)
    net.addLink(s5, s9)
    net.addLink(s8, s9)
    net.addLink(s9, s11)
    net.addLink(s9, s10)
    net.addLink(s10, s11)
    net.addLink(s3, s10)
    net.addLink(s3, s13)
    net.addLink(s10, s13)
    net.addLink(s11, s12)
    net.addLink(s12, s13)

    ## start switch
    for i in range(1,7):
        net.get("s{}".format(i)).start([])

    info( '*** Starting network\n')
    net.start()

    #into the interactive mode
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
