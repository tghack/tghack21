import random
from scapy.all import *
from constants import (
    SIP_PAYLOAD_TYPE,
    SIP_PAYLOAD_TYPE_STRING,
    AUDIO_OUTPUT_DIRECTORY,
    AUDIO_OUTPUT_FORMAT,
    SIP_RTP_AUDIO_CHUNK_SIZE,
)

# https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


class Call:
    def __init__(
        self,
        packet_start_time,
        call_id,
        branch,
        sourcesync,
        caller,
        receiver,
        user_agent,
        character,
    ):
        self.packet_time = packet_start_time
        self.call_id = call_id
        self.branch = f"z9hG4bK{branch}"
        self.sourcesync = sourcesync
        self.caller = caller
        self.receiver = receiver
        self.user_agent = user_agent
        self.character = character

        random_ports = random.sample(range(10000, 65535), 2)
        self.call_port = 5060
        self.rtp_src_port = random_ports[0]
        self.rtp_dst_port = random_ports[1]

        self.packets = []

    def __str__(self):
        return f"<Call call_id={self.call_id} caller={self.caller} receiver={self.receiver} user_agent={self.user_agent} character={self.character} call_port={self.call_port} rtp_src_port={self.rtp_src_port} rtp_dst_port={self.rtp_dst_port}>"

    def _create_sip_packet(self, src_ip, dst_ip, payload):
        pkt = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=self.call_port, dport=self.call_port)
            / self._format_payload(payload)
        )
        pkt.time = self.packet_time
        self.packets.append(pkt)
        self.packet_time += random.uniform(1, 5)

    def _format_payload(self, payload):
        return (
            payload.replace("        ", "")
            .replace("\n", "\r\n")
            .format(
                call_id=self.call_id,
                branch=self.branch,
                user_agent=self.user_agent,
                rtp_src_port=self.rtp_src_port,
                rtp_dst_port=self.rtp_dst_port,
                caller_uri=self.caller.uri,
                caller_ip=self.caller.ip,
                caller_name=self.caller.name,
                receiver_uri=self.receiver.uri,
                receiver_ip=self.receiver.ip,
                receiver_name=self.receiver.name,
                payload_type=SIP_PAYLOAD_TYPE,
                payload_type_string=SIP_PAYLOAD_TYPE_STRING,
            )
        )

    def invite(self):
        payload = """INVITE {receiver_uri} SIP/2.0
        From: {caller_name} <{caller_uri}>
        To: {receiver_name} <{receiver_uri}>
        Call-ID: {call_id}
        CSeq: 1 INVITE
        User-Agent: {user_agent}
        Contact: {caller_uri}
        Max-Forwards: 70
        Content-Type: application/sdp
        Content-Length: 128

        v=0
        o=- 42 42 IN IP4 {caller_ip}
        s=-
        c=IN IP4 {caller_ip}
        t=0 0
        m=audio {rtp_dst_port} RTP/AVP {payload_type}
        a=rtpmap:{payload_type} {payload_type_string}
        a=recvonly
        """
        self._create_sip_packet(self.caller.ip, self.receiver.ip, payload)

    def ok_invite(self):
        payload = """SIP/2.0 200 OK
        Via: SIP/2.0/UDP {caller_ip};branch={branch}
        From: {caller_name} <{caller_uri}>
        To: {receiver_name} <{receiver_uri}>
        Call-ID: {call_id}
        CSeq: 1 INVITE
        User-Agent: {user_agent}
        Contact: <{receiver_uri};transport=udp>
        Content-Type: application/sdp
        Content-Disposition: session
        Content-Length: 283

        v=0
        o=- 1337 1338 IN IP4 {receiver_ip}
        s=-
        c=IN IP4 {receiver_ip}
        t=0 0
        m=audio {rtp_src_port} RTP/AVP {payload_type} 101
        a=rtpmap:{payload_type} {payload_type_string}
        a=fmtp:{payload_type} useinbandfec=1; minptime=10; maxptime=40
        a=rtpmap:101 telephone-event/8000
        a=fmtp:101 0-16
        a=sendonly
        a=ptime:20
        """
        self._create_sip_packet(self.receiver.ip, self.caller.ip, payload)

    def ack_invite(self):
        payload = """ACK {receiver_uri} SIP/2.0
        Via: SIP/2.0/UDP {caller_ip};branch={branch}
        From: {caller_name} <{caller_uri}>
        To: {receiver_name} <{receiver_uri}>
        Call-ID: {call_id}
        CSeq: 1 ACK
        User-Agent: {user_agent}
        Contact: {caller_uri}
        Max-Forwards: 70
        Content-Length: 0

        """
        self._create_sip_packet(self.caller.ip, self.receiver.ip, payload)

    def rtp(self):
        bind_layers(UDP, RTP, dport=self.call_port)
        with open(
            f"{AUDIO_OUTPUT_DIRECTORY}/{self.character}.{AUDIO_OUTPUT_FORMAT}", "rb"
        ) as f:
            audio_file = f.read()
            # Split the file into SIP_RTP_AUDIO_CHUNK_SIZE byte chunks
            audio_chunks = list(
                chunks(audio_file, SIP_RTP_AUDIO_CHUNK_SIZE)
            )  # x byte chunks
        now = 0
        seq_num = 0
        for audio_chunk in audio_chunks:
            # This is just the timestamp for the packet, let's just reuse the chunk size
            now += SIP_RTP_AUDIO_CHUNK_SIZE
            seq_num += 1
            # Generate the RTP packet
            pkt = (
                IP(src=self.receiver.ip, dst=self.caller.ip)
                / UDP(sport=self.rtp_src_port, dport=self.rtp_dst_port)
                / RTP(
                    sequence=seq_num,
                    sourcesync=self.sourcesync,
                    timestamp=now,
                    payload_type=SIP_PAYLOAD_TYPE,
                )
                / audio_chunk
            )
            pkt.time = self.packet_time
            self.packets.append(pkt)

    def bye(self):
        payload = """BYE {caller_uri} SIP/2.0
        Via: SIP/2.0/UDP {receiver_ip};rport;branch={branch}
        Max-Forwards: 70
        From: {receiver_name} <{receiver_uri}>
        To: {caller_name} <{caller_uri}>
        Call-ID: {call_id}
        CSeq: 1337 BYE
        User-Agent: {user_agent}
        Content-Length: 0

        """
        self._create_sip_packet(self.receiver.ip, self.caller.ip, payload)

    def ok_bye(self):
        payload = """SIP/2.0 200 OK
        Via: SIP/2.0/UDP {receiver_ip};rport;branch={branch}
        From: {receiver_name} <{receiver_uri}>
        To: {caller_name} <{caller_uri}>
        Call-ID: {call_id}
        CSeq: 1337 BYE
        User-Agent: {user_agent}
        Contact: <{caller_uri};transport=UDP>
        Content-Length: 0

        """
        self._create_sip_packet(self.caller.ip, self.receiver.ip, payload)

    def create_packets(self):
        # Standard SIP conversation
        self.invite()
        self.ok_invite()
        self.ack_invite()
        self.rtp()
        self.bye()
        self.ok_bye()


class Client:
    def __init__(self, name, username, ip):
        self.name = name
        self.username = username
        self.ip = ip
        self.uri = f"sip:{username}@{ip}"

    def __str__(self):
        return self.uri
