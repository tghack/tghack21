Running `file`, we get 
```bash
$ file treasure
treasure: data
```
and running Cyberchef Entropy we get an entropy score of 7.99. So all we get is an encrypted file. Checking the length of the file.
```python
f = open('treasure','rb').read()
print(len(f))
```
Odd length: 168201, block ciphers create even length output, so most likely a stream-cipher. But there's hundreds so start with the simplest, XOR.

Lets look for parts of potential plaintext keys in case 0x00 bytes in the original file
```python
import re
print(re.findall(b'\w{3,}', f))
```
Lots of output, but we can see
```
[......,b'h3D', b'87Z', b'w4NtB', b'lAt', b'fw9', b'UFMKEYCE', b'EAKEYKEXKEY', b'YKEY', b'3NYJA', b'HEYO', b'ZKE', b'_KEYKDYJE', b'KEY', b'KEY']
```
`KEY` might be a candidate key
```python
from itertools import cycle
open('solved','wb').write(bytes([ord(k)^c for k,c in zip(cycle("KEY"), f)]))
```
```bash
$ file solved
solved: Zip archive data, at least v2.0 to extract
```
We get a zipped text document, grep for TG21 reveals flag