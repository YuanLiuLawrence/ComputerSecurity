#! /bin/sh

# Homework Number: 09
# Name: Yuan Liu
# ECN Login: liu1827
# Due Date: 04/02/2020

# 1: Remove any previous rules or chains
sudo iptables -t filter -F
sudo iptables -t filter -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t nat    -F
sudo iptables -t nat    -X
sudo iptables -t raw    -F
sudo iptables -t raw    -X

# 2: Change source IP to my own IP
sudo iptables -t nat -A POSTROUTING -j MASQUERADE

# 3: Block a list of IP address
sudo iptables -A INPUT -s 123.123.123.123 -j REJECT
sudo iptables -A INPUT -s 125.125.125.125 -j REJECT
sudo iptables -A INPUT -s 222.222.222.222 -j REJECT

# 4: Block from being pinged
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# 5: Set up port-forwarding from an unused port to port 22
sudo iptables -t nat -A PREROUTING -p tcp -d 10.0.2.15 --dport 80 -j DNAT --to-destination 10.0.2.15:22

# 6: Allow for SSH access only from engineering.purdue.edu
sudo iptables -A INPUT -s 128.46.0.0 -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j REJECT

# 7: Allow only a single IP address
sudo iptables -A INPUT -s 124.124.124.124 -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j REJECT

# 8: Permit Auth/Ident
sudo iptables -A INPUT -p tcp --dport 133 -j ACCEPT