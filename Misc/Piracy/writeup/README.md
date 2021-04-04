# Piracy
> Author: Skandix#1269

## Chall
### Description
```
    Ayrrrr, we have gotten reports that you landlubber are not of the old salats, aye?


    We are making a change on that TODAY.....* cough * .
    Lets hope we don't awaken the spirit of Davy Jones' Locker, but yee.
    I've gotten a quest for you lad to find out what the deal with this file is.
    GLHF!
```

### Solution
1. you download ``PirateCheck-v1.0.0-TGHACK.torrent``
2. open it with your favorite torrent download tool (rtorrent ftw)
3. Take a look at the awesome .nfo is a must!
4. look around you find a .svf file
```
piratecheck.part001.rar 338df86f448f1db9d31aefac8fd3b4ca
piratecheck.part002.rar 338df86f448f1db9d31aefac8fd3b4ca
piratecheck.part003.rar 338df86f448f1db9d31aefac8fd3b4ca
...
piratecheck.part203.rar 338df86f448f1db9d31aefac8fd3b4ca
piratecheck.part204.rar 338df86f448f1db9d31aefac8fd3b4ca
piratecheck.part205.rar 338df86f448f1db9d31aefac8fd3b4ca
```
5. we can see a pattern here that ``338df86f448f1db9d31aefac8fd3b4ca`` repeat itself, this migth mean something that this can be good to know
6. try to unrar piratecheck.part001.rar
7. it wants a pw, we try to give it ``338df86f448f1db9d31aefac8fd3b4ca`` as a password.
8. it gives clerance, and inside you find the flag
9. TG21{l00k_4t_th4t_4_tru3_p1rate_wh0_kn0w5_h1s_t4st3_1n_r3l3a5es}
10. plz seed <3