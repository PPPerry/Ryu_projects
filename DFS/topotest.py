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
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s6 = net.addSwitch('s6', cls=OVSKernelSwitch, dpid='0000000000000006')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='0000000000000001')
    s12 = net.addSwitch('s12', cls=OVSKernelSwitch, dpid='0000000000000012')
    s10 = net.addSwitch('s10', cls=OVSKernelSwitch, dpid='0000000000000010')
    s13 = net.addSwitch('s13', cls=OVSKernelSwitch, dpid='0000000000000013')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='0000000000000002')
    s11 = net.addSwitch('s11', cls=OVSKernelSwitch, dpid='0000000000000011')
    s7 = net.addSwitch('s7', cls=OVSKernelSwitch, dpid='0000000000000007')
    s8 = net.addSwitch('s8', cls=OVSKernelSwitch, dpid='0000000000000008')
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch, dpid='0000000000000005')
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='0000000000000003')
    s9 = net.addSwitch('s9', cls=OVSKernelSwitch, dpid='0000000000000009')
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch, dpid='0000000000000004')

    info( '*** Add hosts\n')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None,mac='00:00:00:00:00:02')
    h11 = net.addHost('h11', cls=Host, ip='10.0.0.11', defaultRoute=None,mac='00:00:00:00:00:0b')
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None,mac='00:00:00:00:00:04')
    h10 = net.addHost('h10', cls=Host, ip='10.0.0.10', defaultRoute=None,mac='00:00:00:00:00:0a')
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None,mac='00:00:00:00:00:03')
    h6 = net.addHost('h6', cls=Host, ip='10.0.0.6', defaultRoute=None,mac='00:00:00:00:00:06')
    h8 = net.addHost('h8', cls=Host, ip='10.0.0.8', defaultRoute=None,mac='00:00:00:00:00:08')
    h12 = net.addHost('h12', cls=Host, ip='10.0.0.12', defaultRoute=None,mac='00:00:00:00:00:0c')
    h7 = net.addHost('h7', cls=Host, ip='10.0.0.7', defaultRoute=None,mac='00:00:00:00:00:07')
    h5 = net.addHost('h5', cls=Host, ip='10.0.0.5', defaultRoute=None,mac='00:00:00:00:00:05')
    h9 = net.addHost('h9', cls=Host, ip='10.0.0.9', defaultRoute=None,mac='00:00:00:00:00:09')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None,mac='00:00:00:00:00:01')

    info( '*** Add links\n')
    net.addLink(s3, s4)
    net.addLink(s4, s2)
    net.addLink(s4, s5)
    net.addLink(s5, s6)
    net.addLink(s4, s6)
    net.addLink(s4, s9)
    net.addLink(s9, s10)
    net.addLink(s6, s8)
    net.addLink(s8, s7)
    net.addLink(s8, s10)
    net.addLink(s10, s11)
    net.addLink(s11, s8)
    net.addLink(s7, s13)
    net.addLink(s13, s11)
    net.addLink(s6, s7)
    net.addLink(s10, s12)
    net.addLink(s1, s9)
    net.addLink(h1, s1)
    net.addLink(h2, s2)
    net.addLink(s3, h3)
    net.addLink(h4, s4)
    net.addLink(s5, h5)
    net.addLink(s6, h6)
    net.addLink(s7, h7)
    net.addLink(h8, s8)
    net.addLink(h10, s10)
    net.addLink(h12, s12)
    net.addLink(h11, s11)
    net.addLink(h9, s9)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s6').start([c0])
    net.get('s1').start([c0])
    net.get('s12').start([c0])
    net.get('s10').start([c0])
    net.get('s13').start([c0])
    net.get('s2').start([c0])
    net.get('s11').start([c0])
    net.get('s7').start([c0])
    net.get('s8').start([c0])
    net.get('s5').start([c0])
    net.get('s3').start([c0])
    net.get('s9').start([c0])
    net.get('s4').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

