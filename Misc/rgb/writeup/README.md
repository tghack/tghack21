```pyhton
from PIL import Image
import math

color_sting = ""
pixels = []

with open('colors.txt') as colors:
    color_sting = colors.readlines()

data = color_sting[0].split(" ")
for i in range(0,len(data),4):
    pixels.append((data[i:i+3]))

print(f'Pixels {math.sqrt(len(pixels))*2}')

# 968 pixels
# 484 in each direction as a starting point

## In order to "guess" (not really) more bruteforce -> You have to adjust the correct index according to your loop.
## In this example the height is the inner one, and for that reason you can just manipulate the height until you get a clear image,
## before you then can adjust the widht in order to find the full image

w = 484+80
h = 484-93 # <- Priority one when brute-forcing

img = Image.new('RGB',(w,h))
data = img.load()
i = 0
for x in range(0,w):
    for y in range(0,h):
        data[x,y] = int(pixels[i][0]),int(pixels[i][1]),int(pixels[i][2])
        i += 1
            
img.show()
```