## Writeup

When visiting the page you will most likely attempt to open the pirate chest. This will give you a `forbidden` message, so it seems like we might lack some sort of access.
Check if you have some cookies which might be restricting access. You can spot that you have a token named `jwt` which contains a seemingly strange value. If you query what JWT is, and how to decode it you might stumble upon jwt.io or just simply Cyberchef. 

`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IlNwYWNlIFN3YWIiLCJpYXQiOjE2MTc0NjE0NzJ9.plM6MqgeGhdIkeZ0yeix-M9lgMhXpOJYTCDiaS7byBsSBGu1IHbzcUMElWR45OkRYQ3PsKGqJoh8FWIO3cr8oAh9h4_LErE_04IIxIn0F_8uuQMlhiZEISjmg_OJMZZY1yostxinynPCTtrKNjuMdx8uJy1yHHOFcmN_Vlcgl60EH6yRVz11xVeFZWbGQUBCSN10XvIcHdlA_gZDNYebzwWpiyP-1RGws7xDTXyVk0LVnkTJEcsVgn8UlSgNBHMk2crxaGxsHxs-nL1-y-N5Tpe3D2W-vHzTN0yvysLGK12Dpw5sD8vej02ZNBn-gIM6d6Fsy9R-erIzJyuv3v2lldqMYk4sLY0U7YIUY0FssuZpePgYHrSaSDNbnB6A2TYwTh7VUUcglAkI56QAv-WGBpO_QDn58Lf-HM312U1tV-y8e_M3owFk5DTiYPcNgONrrjqG02j_ZnbvZzOCzrAOGPtmyE0ZINgzveTR5pKEECso6kBl_kBEXQXiJWVbBdDYDvggm_uSPRi8v2Teg2yi-JZtZ-WsWVknnMG_k2lCyHz_N30OOJz3ecE_tidvHlZWOYmREjFVjNR4g7GCEWRFJY5oMN2gpalhz0vc8S_KRDN3p2RqMgI71rZ9RMJgGE2IuRkBi_ptMW98Vf-SpoAb-fj90T_zNhSNSE7sGTsxlEA`

Decoding this token will present you with the following data:

`{"alg":"RS256","typ":"JWT"}{"username":"Space Swab","iat":1617461472}`

According to the text on the webpage it seems like we should prove that we are a pirate for some reason. This is hopefully quite straight forward that we should change our username to pirate, and attempt to access the page again. Changing the username to pirate and then base64 encoding it gives us the following data-part:

`{"username":"pirate","iat":1617461472}`
`eyJ1c2VybmFtZSI6InBpcmF0ZSIsImlhdCI6MTYxNzQ2MTQ3Mn0=`

Seeing as the `payload` part of all JWT tokens are the second one, this is the one we have to replace in the original token we are given. 

JWT structure:
`header.payload.signature`

We changed the payload and will therefore replace this in our JWT token. This gives us for exmaple a token like this:

`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InBpcmF0ZSIsImlhdCI6MTYxNzQ2MTQ3Mn0.plM6MqgeGhdIkeZ0yeix-M9lgMhXpOJYTCDiaS7byBsSBGu1IHbzcUMElWR45OkRYQ3PsKGqJoh8FWIO3cr8oAh9h4_LErE_04IIxIn0F_8uuQMlhiZEISjmg_OJMZZY1yostxinynPCTtrKNjuMdx8uJy1yHHOFcmN_Vlcgl60EH6yRVz11xVeFZWbGQUBCSN10XvIcHdlA_gZDNYebzwWpiyP-1RGws7xDTXyVk0LVnkTJEcsVgn8UlSgNBHMk2crxaGxsHxs-nL1-y-N5Tpe3D2W-vHzTN0yvysLGK12Dpw5sD8vej02ZNBn-gIM6d6Fsy9R-erIzJyuv3v2lldqMYk4sLY0U7YIUY0FssuZpePgYHrSaSDNbnB6A2TYwTh7VUUcglAkI56QAv-WGBpO_QDn58Lf-HM312U1tV-y8e_M3owFk5DTiYPcNgONrrjqG02j_ZnbvZzOCzrAOGPtmyE0ZINgzveTR5pKEECso6kBl_kBEXQXiJWVbBdDYDvggm_uSPRi8v2Teg2yi-JZtZ-WsWVknnMG_k2lCyHz_N30OOJz3ecE_tidvHlZWOYmREjFVjNR4g7GCEWRFJY5oMN2gpalhz0vc8S_KRDN3p2RqMgI71rZ9RMJgGE2IuRkBi_ptMW98Vf-SpoAb-fj90T_zNhSNSE7sGTsxlEA`

Replacing the value in our browser grans us access to the treasure chest, which displays the flag. 

Alternative, if you were to mess a bit more with the challenge you will notice that this web-page actually does not verify the signature used, is simply checks the content of the payload. For this reason we could also do something like this.
`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6InBpcmF0ZSIsImlhdCI6MTYxNTI0MDczOH0.thiswillnotberelevant`