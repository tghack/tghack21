#!/bin/bash
gcc locked-coffer.c -o locked-coffer -fno-stack-protector -z execstack
