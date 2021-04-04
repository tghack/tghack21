#!/bin/bash
gcc squiffy-pirate.c -o squiffy-pirate -fno-stack-protector -z execstack -m32 -no-pie
