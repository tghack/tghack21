# Readme

When going to the page you will find some messages from whoever created the page bragging about how good they are with security and that they have started using certificates for security.
The page also has a link to a treasure chest, which does not seem to be accessible for us at the moment. Attempting to access it results in a forbidden message. Checking our cookies shows us that we have a JWT token which most likely is used to decide our access at the moment. 

This cookie uses RS256 encryption, which means that is uses asymmetrical encryption, e.g it uses a ``private_key`` to encrypt and a ``public_key`` to verify the tokens. Seeing as we have a public key we can easily verify the token we are given, but we cannot create our own tokens using this. Or can we? 

If we change the alg used to HS256 and encrypt the token using the public key found the key should in theory be verified sine HS256 means that the same key should be used to encrypt and decrypt the token. This assumes that the web application accepts the HS256 algortihm as well, which is somewhat common. Since we know what public key is used to decrypt this token, we also know that the same key can be used to encrypt our JWT token if HS256 is used. This encryption can be done in most languages, but often has to use an older JWT library since this feature has been removed from most of the newer versions. However there are also some tools which can do this for us quite simply. For example: `https://github.com/ticarpi/jwt_tool`

In order to use the public key displayed on the page we have to save it to our computer. We save this as RS256.pub. in this case. Remember to have a trailing newline as is required by public keys.

```
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvvyPv40UPeW/b7d+9UMU
gLVQmEVZ+taTwpGuzF/lHm5Zcdado3fhonqxhzjpqson/UyzI8fOBMzSVLDahVo2
Pcv9eHUmQUajF3RZY4nE6xvf9BjVvRP9AdnB8QebV8majWxmZ7cZqDQtzTGZiC5B
SElGgRRGi3/m6CPATWba8W8OrInd7fVxkzZnfeOCOUCmouvPfT1elZ8seoqSJxka
atrn25Aj/ohrGr1PwHl66JFxwcVHqUn5getuMYpG4e4y8GaCUG1BKxQUk9sJbrbQ
u06ofjKXsab+kARr3emOqVUi+yo2M7kmjZwXjV9/4+GWPeh3bMmsEEOljb/7OjLt
VRsU2T9yl72YHFLfWYzsaJNO+oTOQFeeUjkxffTSGzf+0DDfpTzUyojPxqDQfotg
hMGA3Q+DedmKebxDYNmscBwTcit9MIhTbQD/qNzvYNHpqiEBzWY2HwQflT9wqRgm
YR6l0gh4eeg0iisSYzDvMR44xN7SPRSfOwHfHfVjOn6be7u94t5z5X6ZRD9OfP2V
UnoY+rMqW+uNpm6W10sdFePWFQFU8Dgwt8DTUuOcV2ThKSIF/v+jB+kD1N8CCaNx
T99VrHUXjL5dA15zHdODaVbvSs94tI+fgIFllAkPWk2yhEDnkA4LRYhSWn9kAWk2
nUA/lqmEsr4SdogqUmIPoMMCAwEAAQ==
-----END PUBLIC KEY-----

```

A valid token can now be forged by running the following command on the token we are given from the server initially (with a small modifiaction to the payload), as well as using the public key found on the server.
`python3 jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InBpcmF0ZSIsImlhdCI6MTYxNDM0OTEyN30. -S hs256 -k RS256.pub`

Where the payload of the command is changed to:
`eyJ1c2VybmFtZSI6InBpcmF0ZSIsImlhdCI6MTYxNDM0OTEyN30 = {"username":"pirate","iat":1614349127}`

The script will change the algorithm to HS256, and forge the signature.
Changing our JWT token in the browser now lets us access the treaure chest, and gives ut the flag.

Example of a working token:
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InBpcmF0ZSIsImlhdCI6MTYxNDM0OTEyN30.MGhirNy3SDsOPeIRV8a6LsuBLjzWi5_Gt6GovVaJvRs`