import string

FLAG_PREFIX = "TG21{"
FLAG_SUFFIX = "}"

CHARSET = string.ascii_uppercase + string.digits + "$_{}"
PCAP_FILENAME = "dump.pcap"
CALL_ID_FLAG_START = 1337

# In addition to the flag calls, used as noise
RANDOM_VOIP_CALL_COUNT = 1000

# Audio settings
AUDIO_LANGUAGE = "en"
AUDIO_MP3_DIRECTORY = f"./audio_mp3/{AUDIO_LANGUAGE}"
AUDIO_OUTPUT_FORMAT = "alaw"
AUDIO_OUTPUT_DIRECTORY = f"./audio_{AUDIO_OUTPUT_FORMAT}/{AUDIO_LANGUAGE}"

# Codecs
# For a-law
SIP_PAYLOAD_TYPE = 8
SIP_PAYLOAD_TYPE_STRING = "PCMA/8000"
SIP_RTP_AUDIO_CHUNK_SIZE = 160  # bytes

# For Opus
# SIP_PAYLOAD_TYPE = 99
# SIP_PAYLOAD_TYPE_STRING = "opus/48000/2"

# User agents
SIP_USER_AGENT_FLAG = "TGHack SpacePhone 1337"
SIP_USER_AGENTS = [
    "Aastra 480i/1.3.0.1080 Brcm Callctrl/1.5.1 MxSF/v3.2.6.26",
    "Aastra 9133i/1.3.0.1080 Brcm Callctrl/1.5.1 MxSF/v3.2.6.26",
    "Ahead SIPPS IP Phone Version 2.0.50.8",
    "Asterisk PBX",
    "Brcm Callctrl/1.5.1.0 MxSF/v3.2.6.26",
    "Centile-supra",
    "CSCO/4",
    "CSCO/7",
    "Grandstream 1.0.4.39",
    "Grandstream BT100 1.0.4.49",
    "Grandstream BT100 1.0.5.11",
    "Grandstream SIP UA 1.0.4.23",
    "KPhone/3.13",
    "kphone/4.0.4",
    "KPhoneSI/1.0",
    "OmniSession/1.0.0.3",
    "optiPoint 600 office MxSF/v3.5.3.4",
    "MxSipApp/4.4.11.69 MxSF/v3.2.7.30",
    "snom200-2.04l",
    "X-Lite build 1061",
    "X-PRO build 1082",
    "Zultys ZIP 2 3.43",
    "ZyXEL P2000W VoIP Wi-Fi Phone",
    "Cisco-SIPGateway/IOS-12.x",
    "Cisco-CUCM6.1",
    "Nortel PCC 4.1.681",
]

CLIENTS = [
    {
        "name": "Bruce",
        "username": "Bruce.Worsham",
        "ip": "10.13.37.100",
    },
    {
        "name": "Stella",
        "username": "Stella.Romero",
        "ip": "10.13.37.101",
    },
    {
        "name": "Christine",
        "username": "Christine.Jones",
        "ip": "10.13.37.102",
    },
    {
        "name": "Richard",
        "username": "Richard.Fergus",
        "ip": "10.13.37.103",
    },
    {
        "name": "Carolee",
        "username": "Carolee.Kirkpatrick",
        "ip": "10.13.37.104",
    },
    {
        "name": "Joni",
        "username": "Joni.Deacon",
        "ip": "10.13.37.105",
    },
    {
        "name": "John",
        "username": "John.Guenther",
        "ip": "10.13.37.106",
    },
    {
        "name": "Mary",
        "username": "Mary.Lansford",
        "ip": "10.13.37.107",
    },
    {
        "name": "Billy",
        "username": "Billy.Sutton",
        "ip": "10.13.37.108",
    },
    {
        "name": "Glen",
        "username": "Glen.Gustafson",
        "ip": "10.13.37.109",
    },
]
