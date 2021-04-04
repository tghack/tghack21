# CreativeCoding
**Author: Frisk#2559**

**Category: Pwn**

Flags:
1. TG21{Quite_creative_code_you_wrote_there}


Tags: 
1. sandbox
2. coding
3. pwn
4. hard

Files: 
1. no files

Hints: 
1. ${CC} $< -Wall    -o $@   -Wl,-z,norelro -l$(LIBNAME)
2. no binary needed
3. the word Crashing should be Exiting, when the program detects illegal shellcode


---
Can you escape from our sandbox?
nc creativecoding.tghack.no 1337
Author: Frisk#2559

