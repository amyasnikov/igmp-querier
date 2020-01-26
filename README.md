# igmp-querier
Simple IGMPv2 Querier simulator based on Scapy lib. It sends IGMP Query messages and starts/stops sending multicast flow (with random payload) in responce to Join/Leave IGMP messages.

It may be useful for network equipment testing.

Installation:
`pip install scapy
git clone https://github.com/amyasnikov/igmp-querier`

Running:
`cd igmp-querier 
sudo ./querier.py eth0`
