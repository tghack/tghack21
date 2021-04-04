#!/bin/bash
gcc locked-coffer.c -o chal -fno-stack-protector -z execstack
