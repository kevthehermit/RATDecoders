#!/usr/bin/env python
'''
gh0st Rat Config Decoder
'''


__description__ = 'gh0st Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2015/04'

#Standard Imports Go Here
import os
import re
import sys
from base64 import b64decode
from optparse import OptionParser


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(raw_data):
    config_dict = {}
    try:
        install_details = re.findall('CCCCCC(.*?)\x00', raw_data)[-1].split('|')
        domain_details = re.findall('AAAAAA(.*?)\x00', raw_data)[-1]
        if len(install_details) == 2:
            disp_name = install_details[0]
            serv_name = install_details[1]
        config_dict['Display Name'] = decode_strings(disp_name)
        config_dict['Service Name'] = decode_strings(serv_name)
        dom_details = decode_strings(domain_details).split(':')
        if len(dom_details) == 2:
            config_dict['Domain Name'] = dom_details[0]
            config_dict['port'] = dom_details[1]
        elif len(dom_details) == 3:
            config_dict['Domain Name'] = ':'.join([dom_details[0], dom_details[1]])
            config_dict['port'] = dom_details[-1]
        else:
            config_dict['Domain Name'] = dom_details
        return config_dict
    except:
        return

#Helper Functions Go Here

def decode_strings(line):
    decoded = b64decode(line)
    new_string = ''
    for i in range(len(decoded)):
        try:
            val = ord(decoded[i]) - 0x86
            xor = val ^ 0x19
            if xor < 0:
                xor += 256
            new_string += chr(xor)
        except:
            print "Unable to decode character"
            
    return new_string


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
    try:
        print "[+] Reading file {0}".format(args[0])
        fileData = open(args[0], 'rb').read()
    except:
        print "[+] Couldn't Open File {0}".format(args[0])
        sys.exit()
    #Run the config extraction
    print "[+] Searching for Config"
    config = run(fileData)
    #If we have a config figure out where to dump it out.
    if config == None:
        print "[+] Config not found"
        sys.exit()
    #if you gave me two args im going to assume the 2nd arg is where you want to save the file
    if len(args) == 2:
        print "[+] Writing Config to file {0}".format(args[1])
        with open(args[1], 'a') as outFile:
            for key, value in sorted(config.iteritems()):
                outFile.write("Key: {0}\t Value: {1}\n".format(key,value))
    # if no seconds arg then assume you want it printing to screen
    else:
        print "[+] Printing Config to screen"
        for key, value in sorted(config.iteritems()):
            print "   [-] Key: {0}\t Value: {1}".format(key,value)
        print "[+] End of Config"
