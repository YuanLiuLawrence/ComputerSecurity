#!/usr/bin/env python3


from TcpAttack import *


# Your TcpAttack class should be named as TcpAttack
if __name__ == '__main__':

    spoofIP = '192.168.1.2'
    targetIP = '128.46.4.89' # Will contain actual IP addresses in real script
    rangeStart = 0
    rangeEnd = 500
    #port = 22
    Tcp = TcpAttack(spoofIP, targetIP)
    Tcp.scanTarget(rangeStart, rangeEnd)
    print(Tcp.open_ports[0])
    if Tcp.attackTarget(Tcp.open_ports[0], 10):
        print('port was open to attack')