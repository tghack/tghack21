import uuid
import random
from scapy.all import *
from constants import (
    CHARSET,
    CLIENTS,
    FLAG_PREFIX,
    FLAG_SUFFIX,
    PCAP_FILENAME,
    SIP_USER_AGENTS,
    SIP_USER_AGENT_FLAG,
    RANDOM_VOIP_CALL_COUNT,
    CALL_ID_FLAG_START,
)
from utils import generate_call, generate_clients


# Check that we have a valid flag format first
with open("flag") as f:
    FLAG = f.read().strip()
    if FLAG[: len(FLAG_PREFIX)] != FLAG_PREFIX:
        print(f"Flag ({FLAG}) does not match prefix: {FLAG_PREFIX}")
        exit(1)
    elif FLAG[-len(FLAG_SUFFIX) :] != FLAG_SUFFIX:
        print(f"Flag ({FLAG}) does not match suffix: {FLAG_SUFFIX}")
        exit(1)
    for c in FLAG:
        if c not in CHARSET:
            print(f"Invalid flag, character '{c}' is not in charset: {CHARSET}")
            exit(1)


print(f"Generating PCAP ({PCAP_FILENAME}) with FLAG: {FLAG}")

pcap = PcapWriter(PCAP_FILENAME, append=True, sync=True)

# Initialy random source syncs, to be used by the calls
call_count = RANDOM_VOIP_CALL_COUNT + len(FLAG)
sourcesyncs = random.sample(range(0, 1000000), call_count)

# Generate a list of calls
calls = []
call_id_index = 0
packet_start_time = 0

clients = generate_clients(CLIENTS)

# Generate x amount of random voip calls (noise)
for i in range(RANDOM_VOIP_CALL_COUNT):
    # This is mean, let's randomize all the clients
    random_clients = random.sample(clients, 2)
    call = generate_call(
        packet_start_time=packet_start_time,
        call_id=f"{uuid.uuid1()}@sip.tghack.no",
        branch=uuid.uuid1(),
        user_agent=random.choice(SIP_USER_AGENTS),
        sourcesync=sourcesyncs[call_id_index],
        clients=random_clients,
        character=random.choice(CHARSET),
    )
    print(f"[{i + 1}/{RANDOM_VOIP_CALL_COUNT}] Generated random call: {call}")
    calls.append(call)
    call_id_index += 1
    packet_start_time += random.uniform(0, 0.02)

# Generate calls for the flag
flag_call_increment = 0
for i, c in enumerate(FLAG):
    # Randomize clients
    random_clients = random.sample(clients, 2)
    """
    Same arguments as above, we just start with a custom invalid Call-ID and User-Agent
    Flag call IDs should be incremented to easier identify it (for example: 1337, 1338, 1339, etc...)
    """
    # Same arguments as above, we just start with a custom invalid Call-ID and User-Agent
    packet_start_time = random.uniform(1, 40)
    call = generate_call(
        packet_start_time=packet_start_time,
        call_id=CALL_ID_FLAG_START + flag_call_increment,
        branch=uuid.uuid1(),
        user_agent=SIP_USER_AGENT_FLAG,
        sourcesync=sourcesyncs[call_id_index],
        clients=random_clients,
        character=c,
    )
    print(f"[{i + 1}/{len(FLAG)}] Generated flag call: {call}")
    calls.append(call)
    call_id_index += 1
    flag_call_increment += 1
    packet_start_time += random.uniform(0, 0.02)

# Shuffle the calls before sorting the packets
random.shuffle(calls)

# Generate a new packet list based on the time (for mixing packets between calls)
final_packets = []
for call in calls:
    for packet in call.packets:
        final_packets.append(packet)

# To make it simpler we can pre-sort the packets
final_packets.sort(key=lambda packet: packet.time)
# To make it difficult we shuffle the packets, this messes up th
#random.shuffle(final_packets)

# Write the packets to a pcap file
for i, packet in enumerate(final_packets):
    print(f"Writing packet {i + 1}/{len(final_packets)}", end="\r")
    pcap.write(packet)

print(f"\nDone! Created '{PCAP_FILENAME}' with {len(final_packets)} packets.")
