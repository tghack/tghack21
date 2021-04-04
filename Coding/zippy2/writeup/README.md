## Solution 
Create a script that unzips 101 times, and that checks the passwordlist for the password each time.
Messy bash solution:

```bash
#!/usr/bin/sh

for i in {101..1}
do
	cat passwordlist.txt | while read line || [[ -n $line ]];
	do
		unzip -n -P $line archive$i.zip
	done
	echo "Removing: $i"
	rm archive$i.zip
done
```