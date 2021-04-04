## Writeup

Upon accessing the page you are greeted with a button to check your location, and a question if you're home or not yet. Along with this you have a background picture from The Gathering at the Vikingskip. 
When checking your location you are asked to give access to your location, and you will be presented with a message that you're not home yet. Using this information you should manage to think to change your own location to the Vikingskip in Hamar, and by this get `home` as the challange wants you to. Changing your location can be done easily in chrome by using developer tools. This can be done by following this route: 

* CTRL+SHIFT+i
* Click the three buttons at the top right of the window which opens up
* Show console drawer
* Click the three buttons at the top left of the console drawer
* Click on `Sensors`
* Change the location to something which is inside of the Vikingskip
* For example: `60,7929 , 11,1011`
* Check location again and flag should be presented