#!/usr/bin/env python
'''
Crimson Rat Rat Config Decoder
'''
__description__ = 'Crimson Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2015/05/04'

#Standard Imports Go Here
import os
import sys
import string
from optparse import OptionParser
from zipfile import ZipFile
from base64 import b64decode

def run(file_name):
    raw_config = False
    with ZipFile(file_name, 'r') as zip:
        for name in zip.namelist():
            if name == 'com/crimson/bootstrapJar/options':
                raw_config = zip.read(name)
    if raw_config:
        return parse_config(raw_config)
    else:
        return
        
#Helper Functions Go Here
def string_print(line):
    return filter(lambda x: x in string.printable, line)
    
def parse_config(raw_config):
    config_dict = {}
    for line in raw_config.split('\n'):
        if line.startswith('encryption'):
            b64 = b64decode(line.split('<>')[1])
            if b64.endswith('None'):
                config_dict['Encryption'] = 'None'
            elif b64.endswith('AES'):
                config_dict['Encryption'] = 'AES'
            elif b64.endswith('DES'):
                config_dict['Encryption'] = 'DES'
            elif b64.endswith('TRIPPLEDES'):
                config_dict['Encryption'] = 'TRIPPLEDES'
            elif b64.endswith('BLOWFISH'):
                config_dict['Encryption'] = 'BLOWFISH'
        elif line.startswith('key'):
            print '    [!] Traffic Encryption Detected'
            print '    [!] You need to decode the key manually. Sorry'
        else:
            try:
                key, value = line.split('<>')
                config_dict[key] = value
            except:
                pass
    return config_dict

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
            for key, value in sorted(config.iteritems()):
                clean_value = filter(lambda x: x in string.printable, value)
                outFile.write("Key: {0}\t Value: {1}\n".format(key,clean_value))
    # if no seconds arg then assume you want it printing to screen
    else:
        print "[+] Printing Config to screen"
        for key, value in sorted(config.iteritems()):
            clean_value = filter(lambda x: x in string.printable, value)
            print "   [-] Key: {0}\t Value: {1}".format(key,clean_value)
        print "[+] End of Config"
