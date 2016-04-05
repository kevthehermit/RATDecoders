#!/usr/bin/env python
'''
Albertino Rat Rat Config Decoder
'''


__description__ = 'Albertino Rat Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/06/17'

#Standard Imports Go Here
import os
import sys
import string
from struct import unpack
from optparse import OptionParser
from base64 import b64decode
import re

#Non Standard Imports
from Crypto.Cipher import DES

# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
    coded_config = get_config(data)
    decoded_config = b64decode(coded_config)
    raw_config = decrypt_des(decoded_config)
    clean_config = string_print(raw_config)
    return parsed_config(clean_config)
        
#Helper Functions Go Here


def string_print(line):
    return filter(lambda x: x in string.printable, line)

def get_config(data):
    m = re.search('\x01\x96\x01(.*)@@', data)
    raw_config = m.group(0).replace('@','')[3:]
    return raw_config
        
def decrypt_des(data):
    key = '&%#@?,:*'
    iv = '\x12\x34\x56\x78\x90\xab\xcd\xef'
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(data)


def parsed_config(clean_config):
    sections = clean_config.split('*')
    config_dict = {}
    if len(sections) == 7:
        config_dict['Version'] = '4.x'
        config_dict['Domain1'] = sections[0]
        config_dict['Domain2'] = sections[1]
        config_dict['RegKey1'] = sections[2]
        config_dict['RegKey2'] = sections[3]
        config_dict['Port1'] = sections[4]
        config_dict['Port2'] = sections[5]
        config_dict['Mutex'] = sections[6]
    if len(sections) == 5:
        config_dict['Version'] = '2.x'
        config_dict['Domain1'] = sections[0]
        config_dict['Domain2'] = sections[1]
        config_dict['Port1'] = sections[2]
        config_dict['Port2'] = sections[3]
        config_dict['AntiDebug'] = sections[4]
    return config_dict
#Recursive Function Goes Here

def runRecursive(folder, output):
    counter1 = 0
    counter2 = 0
    print "[+] Writing Configs to File {0}".format(output)
    with open(output, 'a+') as out:
        #This line will need changing per Decoder
        out.write("Filename,Version,Domains,Port1,Port2,Mutex,RegKey1,RegKey2,AntiDebug\n")    
        for server in os.listdir(folder):
            fileData = open(os.path.join(folder,server), 'rb').read()
            config_out = run(fileData)
            if config_out != None:
                if config_out['Version'] == '4.x':
                    out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}\n'.format(server, config_out["Version"],config_out["Domain1"],config_out["Domain2"],config_out["Port1"],config_out["Port2"],config_out["RegKey1"],config_out["RegKey2"],config_out["Mutex"],''))
                elif config_out['Version'] == '2.x':
                    out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}\n'.format(server, config_out["Version"],config_out["Domain1"],config_out["Domain2"],config_out["Port1"],config_out["Port2"],'','','',config_out["AntiDebug"]))
                counter1 += 1
            counter2 += 1
    print "[+] Decoded {0} out of {1} Files".format(counter1, counter2)
    return "Complete"

# Main

if __name__ == "__main__":
    parser = OptionParser(usage='usage: %prog inFile outConfig\n' + __description__, version='%prog ' + __version__)
    parser.add_option("-r", "--recursive", action='store_true', default=False, help="Recursive Mode")
    (options, args) = parser.parse_args()
    # If we dont have args quit with help page
    if len(args) > 0:
        pass
    else:
        parser.print_help()
        sys.exit()
    # if we want a recursive extract run this function
    if options.recursive == True:
        if len(args) == 2:
            runRecursive(args[0], args[1])
            sys.exit()
        else:
            print "[+] You need to specify Both Dir to read AND Output File"
            parser.print_help()
            sys.exit()
    
    # If not recurisve try to open file
    try:
        print "[+] Reading file"
        fileData = open(args[0], 'rb').read()
    except:
        print "[+] Couldn't Open File {0}".format(args[0])
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
                clean_value = filter(lambda x: x in string.printable, value)
                outFile.write("Key: {0}\t Value: {1}\n".format(key,clean_value))
    # if no seconds arg then assume you want it printing to screen
    else:
        print "[+] Printing Config to screen"
        for key, value in sorted(config.iteritems()):
            clean_value = filter(lambda x: x in string.printable, value)
            print "   [-] Key: {0}\t Value: {1}".format(key,clean_value)
        print "[+] End of Config"
