# seaGapped

This is a fairly fun and innocent challenge, playing on the term air-gapped a concept which I find quite fascinating. So I decided to make a task around ex-filtrating data from a air gapped system that had a screen saver that displayed it's own memory.

This isn't such a crazy idea as it might seem at first. The way I got this idea was when playing around with Xscreensaver, looking at the different screensavers. then I saw one, named memory that seemed to display my memory contents while the computer was idle! Luckily it wasn't that bad it was just displayed it's own application memory. But an idea was born.

So i set the screensaver to read the contents of a file I provided then just screenshotted the output. 

now to solve it! 

So turns out the encoding was really simple, first byte is the red-value, second -> green-value, third -> blue-value. And thus we have one rgb pixel counting the first three bytes of the output we want. 

Now we just have to write a program to recover the rest of the bytes.

```py
from PIL import Image
from collections import Counter

im = Image.open("../dist/Xscreensaver.png")

data = im.load()
width, height = im.size

output = open("recovered", "wb")

foundStart = False

start, end, wstart  = -1, -1, -1
for w in range(width):
    col = [data[w,h] for h in range(height)]
    cnt = Counter(col)
    start, end  = -1, -1
    for i,c in enumerate(col):
        if col[i] == (0,255,0) and col[i+1] == (0,255,0):
            if start == -1:
                start = i
            elif end == -1:
                end = i
                break
    if len(cnt) > 10:
        wstart = w
        break
print(wstart, start,end)

im1 = im.crop((wstart,start+5,width,end-3))
#im1.show()

data1 = im1.load()
width1, height1 = im1.size

for w in range(0,width1,6):
    col = [data1[w,h] for h in range(height1)]
    cnt = Counter(col)

    for i,c in enumerate(col[::6]):
        bts = bytes(c)
        if bts[0] == bts[1] and bts[0] == bts[2]:
            continue
        output.write(bts)
```

And there we go, the bee move script converted to pirate speak with a flag in the middle
```
...
! I be out! I can'box kite! shiver me timbers! flowers! this here be blue leader. We 'ave roses visual. Brin' it around 30 degrees a. Bringin' it around. Stand to the side, kid. It be got a bit o' a kick. That there be one necta collector! - eose? - no, sir. I pick to the sky some pollen 'ere, sprinkle it o'er 'ere. Maybe a dash o'er there, a pinch on thae a little bit o' magic. That be amazin'. Why do we do that there? that be pollen power. More pollen, more flowers Oool. I be pickin' to the sky a lot o' bright yellow. Oould be daisies. Don't we need them? oopy that there visua TG21{Darn_Y0u_Br0ke_Int0_mY_Sea_Gapped_System:(}  Say again? ye be reportin' a movin' flower? affirmative. That tbe the coolest. What be it? I don't know, but I be lovin' this here color. It smells jolly. Not like a flower, butmical-y. Oareful, scurvy dogs. It be a little grabby. Me sweet lord o' bees! oandy-brain, get off there! problem! be bad. Affirmativ
...
```
