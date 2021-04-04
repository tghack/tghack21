## Solution
By submitting values to the service we can tell that our input is being modified somehow. This in turn should make one think of modification with some sort of key or number. 
Trying the same values multiple times shows that we recieve different output based on which position the character is at. This should make it obvious that this is some sort of XOR manipulation.
In order to brute-force these keys we can submit the same character for all the positions, and then get the output, xor these two, and we should then be left with the xor key. 
This can then be used to retrive the flag.


```python
output = [24,14,20,10,15,14,22,21,9,8,18,17,8,19,0,21,4,6,14,21,21,14,10,4,4,17,21,9,4,3,4,18,21,10,4,24,18,7,14,19,9,8,12,18,4,13,7]
input_to_service = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


xor_string = "".join(chr((a) ^ ord(b)) for a,b in zip(output, input_to_service))
print("XORstring = "+xor_string)


flag_output = [45,40,71,90,21,23,71,6,55,88,0,47,29,26,82,43,7,84,28,0,43,95,25,24]
flag = "".join(chr((a) ^ ord(b)) for a,b in zip(flag_output, xor_string))

print(flag)
```