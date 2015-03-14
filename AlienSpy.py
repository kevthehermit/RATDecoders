#!/usr/bin/env python
'''
AlienSpy Rat Rat Config Decoder
'''
__description__ = 'AlienSpy Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2015/03/03'

#Standard Imports Go Here
import os
import re
import sys
import string
from optparse import OptionParser
from zipfile import ZipFile
from cStringIO import StringIO

#Non Standard Imports
from Crypto.Cipher import ARC4

def run(file_name):
    enckey = coded_jar = False
    with ZipFile(file_name, 'r') as zip:
        for name in zip.namelist():
            if name == 'ID':
                pre_key = zip.read(name)
                enckey = '{0}H3SUW7E82IKQK2J2J2IISIS'.format(pre_key)
            if name == 'MANIFEST.MF':
                coded_jar = zip.read(name)
        
    if enckey and coded_jar:
        decoded_data = decrypt_RC4(enckey, coded_jar)
        decoded_jar = StringIO(decoded_data)
    else:
        return

    with ZipFile(decoded_jar) as zip:
        for name in zip.namelist():
            if name == 'config.xml':
                raw_config = zip.read(name)
    return parse_config(raw_config)
        
#Helper Functions Go Here

def string_print(line):
    return filter(lambda x: x in string.printable, line)

####RC4 Cipher ####	
def decrypt_RC4(enckey, data):
	cipher = ARC4.new(enckey) # set the ciper
	return cipher.decrypt(data) # decrpyt the data

def parse_config(raw_config):
    config_dict = {}
    for line in raw_config.split('\n'):
        if line.startswith('<entry key'):
            config_dict[re.findall('key="(.*?)"', line)[0]] = re.findall('>(.*?)</entry', line)[0]
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
