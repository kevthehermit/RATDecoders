#!/usr/bin/env python
'''
Tapaoux Config Extractor
'''
__description__ = 'Tapaoux Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2015/05/11'

import re
import sys
import string
from operator import xor
from optparse import OptionParser


keys = ['Error Code', 'Last Error', '(R) Microsoft Corporation.']

marker_1 = '\xFF\xC3\x4C\xFF\xFC\xCC\x22\xCC\xAA\xAF\x32\x00\x0A\x7C\x44\x4D'
marker_2 = '\xFF\x3C\xC4\xFF\xFC\xCC\x22\xCC\xAA\xAF\x32\x00\x0A\x7C\x44\x4D'

def string_clean(line):
    return ''.join((char for char in line if 32< ord(char) < 127))

def find_config(file_data):

    split_data = file_data.split(marker_1)
    if len(split_data) < 2:
        split_data = file_data.split(marker_2)
    if len(split_data) == 2:
        return split_data[1][:500]
    
def config_decrypt(keys, data):
    for enc_key in keys:
        print "    [-] Testing for Key: {0}".format(enc_key)
        key_pointer = 0
        decoded = ''
        for i in range(len(data)):
            if key_pointer >= len(enc_key):
                key_pointer = 0
                
            data_slice = ord(data[i])
            key_slice = ord(enc_key[key_pointer])
            if data_slice == key_slice or data[i].encode('hex') == '00':
                decoded += data[i]
            else:
                decoded += chr(xor(data_slice, key_slice))
            key_pointer += 1
        
        conf_test = re.search('/[a-zA-Z0-9-]*\x2ephp', decoded)
        if conf_test:
            print "  [-] Found Config"
            return string_clean(decoded)

if __name__ == "__main__":
    parser = OptionParser(usage='usage: %prog inFile\n' + __description__, version='%prog ' + __version__)
    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        sys.exit()
        
    print "[+] Reading File"
    file_data = open(args[0], 'rb').read()
    print "  [-] Searching for config"
    config_section = find_config(file_data)
    if config_section == None:
        print "[!] Config Not Found"
        sys.exit()
    dec_config = config_decrypt(keys, config_section)
    print "----------------------"
    print dec_config
    print "----------------------"
    print "[+] Complete"
        
