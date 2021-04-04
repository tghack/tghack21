Use `xxd` on the file, one can recognize the magic header bytes `78 9c` in reverse order which is zlib standard compression.
```bash
$ xxd strange_file
00000000: 540b a2a9 17fb 74ce e34e 3d82 aea7 bd13  T.....t..N=.....
00000010: bca9 a537 2873 0e20 af06 2ac6 bbe0 3d7e  ...7(s. ..*...=~
...[snip]...
00000490: 3c9f 5ec2 d020 1210 8042 72b8 2451 ee68  <.^.. ...Br.$Q.h
000004a0: afcf bc10 34e4 af4d 5665 9c78            ....4..MVe.x
```

Script to reverse and decompress the zlib blob
```python
import zlib
file_content = open('strange_file','rb').read()[::-1]
decompressed = zlib.decompress(file_content)
open('uncompressed', 'wb').write(decompressed)
```
```bash
$ file uncompressed
uncompressed: ASCII text, with very long lines
```
The flag is in between lorem ipsum