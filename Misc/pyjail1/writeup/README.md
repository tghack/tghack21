## Writeup
There is not much restricitve in this task, and we can tell that we have been dropped in some sort of python application by the `>>>` at the start of our input line. 
Since this is a breakout challange we can attempt to access some sort of internal os/system commands through output, and hopefully get the flag that way.
There are a ton of solutions to this challenge, and this is just one of them.

Can be solved by accessing `os` and reading the flag with cat
`__import__('os').system('cat flag')`