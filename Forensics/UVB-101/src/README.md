To generate the capture for this data:

1. Get an FM transmitter and a receiever (RTL-SDR, HackRF, etc.)
2. Set the transmitter to 101.0MHz and start listening on that frequency with a samplerate of 250000Hz
```
$ rtl_sdr -f 101M -g 40 -s 250000 -p 6 capture.raw
Found 1 device(s):
  0:  Realtek, RTL2838UHIDIR, SN: 00000001

Using device 0: Generic RTL2832U OEM
Found Rafael Micro R820T/2 tuner
Exact sample rate is: 250000.000414 Hz
Sampling at 250000 S/s.
Bandwidth set to automatic resulted in 290000 Hz.
Tuned to 101.000000 MHz.
Tuner gain set to 40.20 dB.
Tuner error set to 6 ppm.
Reading samples in async mode...
Allocating 15 zero-copy buffers
```
3. Translate the raw flodata capture into floats, so that Gqrx and other programs can read it.
`sox -t raw -r 250000 -b 8 -c 1 -e unsigned-integer capture.raw  -t raw -r 250000 -c 1 -e float capture.iq`

4. To load the capture we specify the following settings
`file=./capture.iq,rate=2.5e5`

