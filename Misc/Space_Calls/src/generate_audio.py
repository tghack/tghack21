import os
from glob import glob
from pydub import AudioSegment

language = "en"
mp3_directory = f"./audio_mp3/{language}"
output_directory = f"./audio_alaw/{language}"
output_format = "alaw"


"""
import string
from gtts import gTTS
audio_directory = "test"
charset = string.ascii_uppercase + string.digits + "@$_{}"
# Use this to generate audio with gTTS
for c in charset:
    print(f"Generating audio for '{c}'")
    tts = gTTS(c, lang=language)
    audio_file = f"./{audio_directory}/{c}"
    tts.save(f"{audio_file}.mp3")
    exit(0)
"""

for f in glob(f"{mp3_directory}/*.mp3"):
    audio_file = os.path.splitext(os.path.basename(f))[0]
    print(f"Converting {audio_file}")
    sound = AudioSegment.from_mp3(f)
    sound = sound.set_frame_rate(8000)
    sound.export(
        f"{output_directory}/{audio_file}.{output_format}",
        format=output_format,
        bitrate="8k",
    )
