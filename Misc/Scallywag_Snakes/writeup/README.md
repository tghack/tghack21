# ScallyWag_Snakes
> Author: Skandix#1269

## Chall
### Description
```
Yarr, the ship is full of snakes, can you find what they are looking for, or what they at least WAAANT!?
```

### Solution
#### Simple Solution
> should have used pyarmor >:)

1. download snakes.pyc
2. strings snakes.pyc | grep tg21


#### Hard Solution
1. Download the snakes.pyc
2. Try to run it with python3 snakes.pyc
3. and the the output
```
HAPPY MALWARE




SAYS HELLO :)
tbysgnatbgjbbar{tbysoeniboeniboenib_tbyshavsbezebzrb_mhyhoeniboenibnysn_whyvrggivpgbetbyshavsbez_puneyvryvzntbyshavsbezoenibnysn}
```
4. we will focus on the last part ``tbysgnatbgjbbar{tbysoeniboeniboenib_tbyshavsbezebzrb_mhyhoeniboenibnysn_whyvrggivpgbetbyshavsbez_puneyvryvzntbyshavsbezoenibnysn}``
5. if we throw this into cyberchef and add the rot13 recipie, you will get a new readable output ``golftangotwoone{golfbravobravobravo_golfuniformromeo_zulubravobravoalfa_juliettvictorgolfuniform_charlielimagolfuniformbravoalfa}``
6. If one is familiar with the Phonetic alphabet one can see that the output is now readable but it's all phumbled all into each other, we can now see that in the start it says ``twoone`` this indicates that part of the flag is still intact.
7. This is a hint to that it's still just rot13 encoded, since numbers are not affected with rot13(numbers need to be written as ints and not strings ;) ) as it only encodes alphanumeric characters, and that we take the first letter from each word and put into a new sentence, and keep the curly braces along with the underscores . we will get something like this.
![](https://i.imgur.com/BqLciRr.png)
8. Slap this thing into cyberchef with another rot13 and waphaaow``gt21{gbbb_gur_zbba_jvgu_clguba}``
9. FLAG: ``tg21{tooo_the_moon_with_python}``

