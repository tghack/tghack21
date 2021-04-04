Rowboat kind of sound like robot, so navigate to robots.txt. Looking at the traffic we can notice that robots.txt returned `html`, not `text` as it usually does. So checking the source we see

`All the robots say <!-- /68ce70a009c7f12ccdc6a9d3b461fa90 -->`

, navigating to that page and checking the source we see

`You got it matey! <!-- 4 o /3ca5753b324ea3ec2c3865bc541f1294 -->`

Looking at a few of the other pages page we see a structure:
```
<!-- <character index> <character> <another page> -->
```

Complete solver script
```python
import requests
import re

base = 'http://rowboat.tghack.no:1337'
solved = ['']*500
find = re.compile(r"<!-- (\d+) (.) /([a-f0-9]+)")
r = requests.get(f'{base}/robots.txt').text
_next = re.search(r"/([a-z0-9]+)", r).groups(1)[0]
for _ in range(1000):
    r = requests.get(f'{base}/{_next}').text
    i,c,_next = find.search(r).groups()
    solved[int(i)] = c
    print(f'\r{"".join(solved)}', end='')
```