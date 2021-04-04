# Smørbrød
> Author: Skandix#1269

## PatchNotes
* 1.0 - There was an easy solution where as I had forgot to remove photoshop metadata :FeelsBadMan:
* 1.2 - No more easypeasy solutions >:)

## Chall
### Description
```
Ayy, one of mine pirate lads created this obscure sandwich with this norwegian brown cheese,
    they hid a pirate flag in it can you see if you are hungry enough to find it ?
```

### Solution
1. Download ``smørbrød.png``
2. Start inspecting the image
3. you can already see that underneath the brown cheese there's a tiny bit of the start of the flag peeking out.
4. First by binwalking the picture you migth see this
```
[19:47:47] skandix@Sheepy λ binwalk smørbrød.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1765 x 2147, 8-bit/color RGBA, non-interlaced
41            0x29            Zlib compressed data, best compression
1168979       0x11D653        rzip compressed data - version 35.-84 (-1788549760 bytes)
8480894       0x81687E        PNG image, 1765 x 2147, 8-bit/color RGBA, non-interlaced
8480935       0x8168A7        Zlib compressed data, best compression
12054158      0xB7EE8E        Zip archive data, encrypted at least v2.0 to extract, compressed size: 16138236, uncompressed size: 16141991, name: 2.png
28192548      0x1AE2F24       End of Zip archive, footer length: 22
```
Here we can start seeing that as it's with the smørbrød having multiple layers to create such an incredible smørbrød,
the file itself also contains several layers.
From the binwalk we can see it contains two PNG files,
and a zip archive, one can speculate to see that since there's already two png files and a zip inside the single png, that more migth be hidden in the zip file.

...


We can extract all the files from smørbrød by using binwalk to extract it for us, you can also use dd if you are feeling adventurous (USE DD WITH CAUTION!)
But with binwalk i can extract its files by doing binwalk smørbrød.png --dd='.*' Which will give you a folder called ``_smørbrød.png.extracted``


...


On first glance on the zip file it appeears locked, which it is :D.
You need to look around and find it's password which can be located at the end of the smørbrød file, which is this phrase.
``62 72 75 6e 6f 73 74 5f 65 72 5f 76 65 72 64 65 6e 73 5f 62 65 73 74 65 5f 74 79 70 65 5f 6f 73 74``
For those who are not familiar with this, this is string is encoded with hex. I'll get [Cyberchef](https://gchq.github.io/CyberChef/) to decode this for me as i'm not so hardcore that i'll do it manually :joy:
Then we will get ``brunost_er_verdens_beste_type_ost``
Since we are missing a password for the zip file we will try using that as our password.
And BOOOM, we can then proceed to unzip the remaining file which is a single .png
Open that up and you will see the flag on the last slice of bread :D

**FLAG: TG21{something_feels_a_sl1c3_or_b1t_0f_ch33sy}**

#### How I planned the layers

| Filename | Description |
| -------- | ----------- |
| 0.png    | Full        |
| 1.png    | Brunost     |
| 2.png    | Flag        |
| 3.png    | Bread       |

```
{ 0.png }
	|--- {1.png} (pw til zip)
			|--- {bruunost.zip}
					|--- {2.png}
							|--- {3.png}
```
