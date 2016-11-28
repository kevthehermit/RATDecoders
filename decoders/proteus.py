#!/usr/env python2
# works on config strings as well as POST data
import fileinput
for line in fileinput.input():
    hexblob = line.replace("\\\\x","\\").replace("\\x","\\").split("\\")
    num = (len(hexblob) - 1) / 2
    text = ''
    text2 = ''
    for i in range(len(hexblob)):
        if hexblob[i] != "":
            if i <= num:
                text += chr(int(hexblob[i], 16) ^ num)
            else:
                text2 += chr(int(hexblob[i], 16) ^ ord(text[i - num -1]))
    print text2
