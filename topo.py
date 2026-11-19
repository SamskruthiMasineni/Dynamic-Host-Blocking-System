#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def build():
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True)

    info("*** Adding controller\n")
    net.addController("c0", controller=RemoteController,
                      ip="127.0.0.1", port=6653)

    info("*** Adding switch\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    info("*** Adding hosts\n")
    hosts = []
    for i in range(1, 7):
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
        net.addLink(h, s1)
        hosts.append(h)

    net.start()
    info("*** Network ready: h1=server, h2-h4=normal clients, h5-h6=attackers\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build()
