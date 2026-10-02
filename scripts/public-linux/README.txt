MADAR Node for Linux (x86-64)
=============================

A regular node that verifies blocks on the MADAR test network. It does not vote and holds no keys or funds.
Runs on: Ubuntu 24.04 or newer, Debian 13 or newer, Linux Mint 22 or newer (64-bit CPU, glibc 2.38+).

1) Extract:            tar -xzf MADAR-Node-linux-x64.tar.gz && cd MADAR-Node-linux-x64
2) Verify:             sha256sum -c SHA256SUMS.txt
3) Run:                ./madar-node.sh start --name YOUR_NAME
4) Status:             ./madar-node.sh status
5) Stop:               ./madar-node.sh stop
6) Start with the PC:  ./madar-node.sh service

"Help the network" (optional): ./madar-node.sh start --help-network — your node accepts connections from other nodes
(open port 30333/TCP in your firewall). Without it: outbound connections only, no open port.
Data lives in: ~/.local/share/madar-node — delete it to remove everything.
Terms and privacy policy: https://madar-network.com — security reports: contact@madar-network.com
