#!/usr/bin/env python
'''
Sakula Rat Rat Config Extractor
'''
__description__ = 'Sakula Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2015/11/10'

#Standard Imports Go Here
import os
import re
import sys
import string
from struct import unpack
from optparse import OptionParser
from Crypto.Cipher import XOR

def run(file_name):
    file_data = open(file_name, 'rb').read()
    # RE for 1.0 and 1.1
    re_pattern1 = r'([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})(.{12}\x77\x77\x77\x77)'
    # RE for 1.2, 1.3, 1.4
    re_pattern2 = r'([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{12})(0uVVVVVV)'
    
    
    # XOR for Version 1.0
    
    xor_data = xor_file(file_data, '\x88')
    config_list = re.findall(re_pattern1, xor_data)
    
    for c in config_list:
        if any(".exe" in s for s in c):
            print "Found Version < 1.3"
            configs = config_v1(config_list)
            return configs
    
    # XOR for later versions

    xor_data = xor_file(file_data, 'V')
    config_list = re.findall(re_pattern2, xor_data)

    for c in config_list:
        if any(".exe" in s for s in c):
            print "Found Version > 1.2"
            configs = config_v2(config_list)
            return configs
  
def config_v1(config_list):
    config_dict = {}
    counter = 1
    for config in config_list:
        config_dict['Domain'] = config[0].rstrip('\x88')
        config_dict['URI GET1 Folder'] = config[1].rstrip('\x88')
        config_dict['URI GET3 File'] = config[2].rstrip('\x88')
        config_dict['URI GET2 File'] = config[3].rstrip('\x88')
        config_dict['URI GET3 Arg'] = config[4].rstrip('\x88')
        config_dict['Copy File Name'] = config[5].rstrip('\x88')
        config_dict['Service Name'] = config[6].rstrip('\x88')
        config_dict['Service Description'] = config[7].rstrip('\x88')
        config_dict['Waiting Time'] = unpack('>H', str(config[8][:2].rstrip('\x88')))[0]
        counter += 1
    return config_dict
            
    
def config_v2(config_list):
    config_dict = {}
    counter = 1
    for config in config_list:
        config_dict['{}_Domain'.format(counter)] = config[0].rstrip('V')
        config_dict['{}_URI GET1 Folder'.format(counter)] = config[1].rstrip('V')
        config_dict['{}_URI GET3 File'.format(counter)] = config[2].rstrip('V')
        config_dict['{}_URI GET2 File'.format(counter)] = config[3].rstrip('V')
        config_dict['{}_URI GET3 Arg'.format(counter)] = config[4].rstrip('V')
        config_dict['{}_Copy File Name'.format(counter)] = config[5].rstrip('V')
        config_dict['{}_AutoRun Key'.format(counter)] = config[6].rstrip('V')
        config_dict['{}_Copy File Path'.format(counter)] = config[7].rstrip('V')
        config_dict['{}_Campaign ID'.format(counter)] = config[8].rstrip('V')
        config_dict['{}_Waiting Time'.format(counter)] = unpack('<H', str(config[9][:2].rstrip('V')))[0]
        counter += 1
    return config_dict
        
    
def xor_file(file_data, key):
    cipher = XOR.new(key)
    return cipher.decrypt(file_data)


# Main
if __name__ == "__main__":
    parser = OptionParser(usage='usage: %prog inFile outConfig\n' + __description__, version='%prog ' + __version__)
    (options, args) = parser.parse_args()
    # If we dont have args quit with help page
    if len(args) > 0:
        pass
    else:
        parser.print_help()
        sys.exit()
    #Run the config extraction
    print "[+] Searching for Config"
    config = run(args[0])
    #If we have a config figure out where to dump it out.
    if not config:
        print "[+] Config not found"
        sys.exit()
    #if you gave me two args im going to assume the 2nd arg is where you want to save the file
    if len(args) == 2:
        print "[+] Writing Config to file {0}".format(args[1])
        with open(args[1], 'a') as outFile:
            print "[+] Printing Config to screen"
            for key, value in sorted(config.iteritems()):
                print "   [-] Key: {0}\t Value: {1}".format(key,value)
            print "[+] End of Config"
    # if no seconds arg then assume you want it printing to screen
    else:
        print "[+] Printing Config to screen"
        for key, value in sorted(config.iteritems()):
            print "   [-] Key: {0}\t Value: {1}".format(key,value)
        print "[+] End of Config"
