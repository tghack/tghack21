## Solution 
Create a script to unzip 1337 times. Bash solution:

```bash
#!/usr/bin/sh

for i in {1337..1}
do
	echo "Number: $i"
	unzip archive$i.zip
	rm archive$i.zip
done
```
