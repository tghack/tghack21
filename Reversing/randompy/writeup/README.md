## Writeup

We are given a compiled python script, so have to decompile this first with for example: `https://github.com/rocky/python-decompile3`

Command:  `decompyle3 chal.pyc`

Solve script:

```python

import random

# Output fetched from one of the challenge
known_secret = "l]WKuocjoXtabtoZGiVQ`rYUkWDmdVsM^Nf{A"
flag2 = "10110101101100101001011010001001101011001010110110110000011010100110111010001111110000110101111110011110101101111011001010101111011111101000101110001011100011000111010110101111100101011001111001101101100100010111000110101101101010001001100110110101100001001001010110100110101100011011010110010101"
flag = []

# First have to transform the binary string to hex values
for sp in range (0,(len(flag2)),8):
    flag.append((int(flag2[sp:sp+8],2)))

#  Brute-force seed for the random values
seed1 = ""
for i in range (0,100000):
    random.seed(i)
    secret = []

    for x in range (0,len(flag)):
        secret.append((random.randint(65,125)))

    secret_part2 = [chr(x) for x in secret]
    test_secret = ''.join(secret_part2)
    if test_secret == known_secret:
        print(f"Found seed: {i}")
        seed1 = i
        break

# secret seed is now known

# Now we have to go through the same steps as in the original seed to keep the seed valid
secret = []
secret2 = []
random.seed(seed1)
for i in range (0,len(flag)):
    secret.append((random.randint(65,125)))
    
for i in range (0,len(flag)):
    secret2.append((random.randint(0,1)))

# Has to do the excact same random in order for the seed to work
for i in range(0,50):
    garbage = random.randint(0,1)

# Create mapping from shuffle
new_arr = []
for i in range (0,len(flag)):
    new_arr.append(i)

# Seed still the same so can do this
random.shuffle(new_arr)

# Go through the last steps in reverse
c = [(((x))+50) for x in flag]
for v in range (1,len(flag)):
    if secret2[v]:
        c[v] = c[v] - 13

c2 = [c[i]-(secret[i]) for i,j in enumerate(flag)]
c2 = [(chr(x)) for x in c2]

# Then use the mapping to get the original falg back in the correct order
test = {}
for i in range(0,len(c2)):
    value = f"{c2[i]}"
    test[new_arr[i]] = value

solved_flag = ""
for key in sorted(test.keys()):
    solved_flag += str(test[key])
print(solved_flag)



```