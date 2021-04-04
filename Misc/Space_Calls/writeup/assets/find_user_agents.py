import re
from scapy.all import *

"""
If the port is absent, the default value depends on the transport.
It is 5060 for UDP, TCP and SCTP, 5061 for TLS.

- RFC 3261 - 18.1.1 Sending Requests
  https://tools.ietf.org/html/rfc3261#section-18.1.1
"""
"""
It is also RECOMMENDED that a server
listen for requests on the default SIP ports (5060 for TCP and UDP,
5061 for TLS over TCP) on all public interfaces.

- RFC 3261 - 18.1.2 Receiving Requests
https://tools.ietf.org/html/rfc3261#section-18.1.2
"""
SIP_PORT = 5060

# Load the packets from the PCAP
print("Loading PCAP into memory, this might take a while...")
packets = rdpcap("dump.pcap")
print(f"Loaded {len(packets)} into memory")

# Find all SIP packets and print out the user agents.
user_agents = set()
for packet_number, packet in enumerate(packets):
    # print(f"Reading packet {packet_number + 1}/{len(packets)}", end="\r")
    if packet.haslayer(UDP):
        udp = packet[UDP]
        payload = udp.payload.load

        # We only want SIP packets
        if udp.sport != SIP_PORT:
            continue

        # We have SIP packet!
        payload = payload.decode("utf-8")

        # User-Agent: TGHack SpacePhone 1337
        user_agent = re.search(r"User-Agent: (.*)\r\n", payload).group(1)

        user_agents.add(user_agent)

user_agents = sorted(list(user_agents))
for user_agent in user_agents:
    print(user_agent)
