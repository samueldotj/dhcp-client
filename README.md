dhcp-client
===========

A simple DHCP client written in 500 lines of C code.

Uses pcap library to read/write packets on the network interface.
This program sends out DHCP DISCOVER packet on the given interface and
waits for DHCP OFFER. 

It works on Linux and FreeBSD.
