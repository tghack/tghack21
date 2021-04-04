## Writeup

Decompile the pyc file using for exmaple `https://github.com/rocky/python-decompile3`
Command: `decompyle3 chal.pyc`

Solve script:

```python

starting_values = ["0x522",
"0x333",
"0x980",
"0x623",
"0x1141",
"0x1127",
"0x414",
"0x1099",
"0x405",
"0x994",
"0x612",
"0x423",
"0x405",
"0x612",
"0x637",
"0x994",
"0x594",
"0x594",
"0x1127",
"0x405",
"0x959",
"0x1316",
"0x594",
"0x637",
"0x405",
"0x1442",
"0x1057",
"0x405",
"0x1043",
"0x414",
"0x1330",
"0x1099",
"0x594",
"0x994",
"0x1442",
"0x423",
"0x495"]

clean_values = []
for x in starting_values:
    clean_values.append(int(x[2:]))

solved = ""
for ch in clean_values:
    if (ch % 3) == 0:
        if (int((ch/3)-40) % 2) == 0:
            solved += (chr(int(ch/3)-90))
        else:
            solved += (chr(int(ch/3)-40))
    if (ch % 7) == 0:
        if (int((ch/7)-40) % 2) == 0:
            solved += (chr(int(ch/7)-90))
        else:
            solved += (chr(int(ch/7)-40))
print(solved)

```