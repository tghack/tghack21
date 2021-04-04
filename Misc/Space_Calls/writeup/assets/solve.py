import re
import io
import collections
from scapy.all import *
from pydub import AudioSegment

# We know the user agent, let's just check the packets with this user-agent
FLAG_USER_AGENT = "TGHack SpacePhone 1337"

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

# From one of the calls:
"""
m=audio 18492 RTP/AVP 8
a=rtpmap:8 PCMA/8000
"""

"""
The MIME type (audio) goes in SDP "m=" as the media name.

- RFC 4040 - 5. Mapping to Session Description Protocol
  https://tools.ietf.org/html/rfc4040#section-5
"""
"""
a=rtpmap:<payload type> <encoding name>/<clock rate> [/<encoding parameters>]
     This attribute maps from an RTP payload type number (as used in
     an "m=" line) to an encoding name denoting the payload format
     to be used.  It also provides information on the clock rate and
     encoding parameters.  It is a media-level attribute that is not
     dependent on charset.

- RFC 4566 - 6. SDP Attributes
  https://tools.ietf.org/html/rfc4566#section-6
"""
"""
For example, a session directory could specify that for a
given session, payload type 96 indicates PCMU encoding, 8,000 Hz
sampling rate, 2 channels

PT    encoding    media type  clock rate   channels
      name                    (Hz)
___________________________________________________
 8    PCMA        A            8,000       1

- RFC 3551 - 6. Payload Type Definitions
  https://tools.ietf.org/html/rfc3551#section-6
"""
PAYLOAD_TYPE = 8

# Load the packets from the PCAP
print("Loading PCAP into memory, this might take a while...")
packets = rdpcap("dump.pcap")
print(f"Loaded {len(packets)} into memory")

"""
Let's find all the calls containing the user agent and map them,
and note which ports they use to communicate
"""
rtp_port_call_mapping = {}
for packet_number, packet in enumerate(packets):
    print(f"Reading packet {packet_number + 1}/{len(packets)}", end="\r")
    if not packet.haslayer(UDP):
        continue

    udp = packet[UDP]
    payload = udp.payload.load

    # We don't want to parse the RTP packets just yet.
    if udp.sport != SIP_PORT:
        continue

    # We have SIP packet!
    payload = payload.decode("utf-8")

    # User-Agent: TGHack SpacePhone 1337
    user_agent = re.search(r"User-Agent: (.*)\r\n", payload).group(1)
    # We only need the packets with our user agent
    if user_agent != FLAG_USER_AGENT:
        continue

    # We only need the initial invite SIP/SDP packet as it contains all the information
    if "INVITE sip:" not in payload:
        continue

    """
    The Call-ID header field acts as a unique identifier to group
    together a series of messages.  It MUST be the same for all requests
    and responses sent by either UA in a dialog.  It SHOULD be the same
    in each registration from a UA.

    - RFC 3261 - 8.1.1.4 Call-ID
      https://tools.ietf.org/html/rfc3261#section-8.1.1.4
    """
    # Call-ID: 1337
    call_id = int(re.search(r"Call-ID: (.*)\r\n", payload).group(1))

    """
    Audio and video are typically sent using RTP [RFC3550], which
    requires two UDP ports, one for the media and one for the control
    protocol (RTCP).

    - RFC 3605 - 1. Introduction
      https://tools.ietf.org/html/rfc3605
    """
    # m=audio 18492 RTP/AVP 8
    # 18492 = destination port
    rtp_dst_port = int(
        re.search(
            r"m=audio (.*) RTP/AVP {payload_type}\r\n".format(
                payload_type=PAYLOAD_TYPE
            ),
            payload,
        ).group(1)
    )
    rtp_port_call_mapping[rtp_dst_port] = call_id

print()
print(f"Found {len(rtp_port_call_mapping)} RTP ports")

"""
We now have a mapping of all the relevant calls and their ports.
Let's now go through all of the RTP packets and check if the port
is in the list that we know the flag calls use.
"""
flag_calls = collections.defaultdict(bytes)
for packet_number, packet in enumerate(packets):
    udp = packet[UDP]
    if udp.dport not in rtp_port_call_mapping:
        continue
    print(f"Found flag RTP packet @ #{packet_number + 1}")
    call_id = rtp_port_call_mapping[udp.dport]
    """
    We have a RTP packet and its Call-ID,
    extract the raw audio and append the data
    for that flag to the call
    """
    raw = udp.payload.load[11:].replace(b" ", b"")
    flag_calls[call_id] += raw

# Let's sort the Call-ID-s as we see they start with 1337 and are sequential
flag_calls = collections.OrderedDict(sorted(flag_calls.items()))

print(f"We have a total of {len(flag_calls)} flag calls, Call-IDs:")
print(list(flag_calls.keys()))

# Loop through the flag calls and append the raw audio to a variable
flag = b""
for call_id, flag_call in flag_calls.items():
    flag += flag_call

# Load the a-law audio into memory instead of saving into a file, and finally convert export it to mp3
f = io.BytesIO(flag)

# Equivalent of doing: ffmpeg -f alaw -ar 8000 -i flag.alaw flag.mp3
sound = AudioSegment.from_file(f, "alaw")
sound = sound._spawn(sound.raw_data, overrides={"frame_rate": 8000})
sound.export("flag.mp3", format="mp3")

print("Wrote the flag to flag.mp3")

# sox and ffmpeg can be used in a terminal instead to convert the raw a-law data:
# sox --channels 1 --type raw --rate 8000 -e a-law flag.alaw flag.wav
# ffmpeg -f alaw -ar 8000 -i flag.alaw flag.wav
# ffmpeg -f alaw -ar 8000 -i flag.alaw flag.mp3
