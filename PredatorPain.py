#!/usr/bin/env python
'''
Predator Pain and Hawkeye
'''


__description__ = 'Predator Pain and Hawkeye Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2015/06/10'

#Standard Imports Go Here
import os
import sys
import base64
import string
from struct import unpack
from optparse import OptionParser

#Non Standard Imports
try:
    import pype32
except ImportError:
    print "[+] Couldn't Import pype32 'https://github.com/crackinglandia/pype32'"
from Crypto.Cipher import AES
from base64 import b64decode
from pbkdf2 import PBKDF2

# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python config_dict of values
'''

def run(data):
        pe = pype32.PE(data=data)

        print "  [-] Collecting Strings"
        string_list = get_strings(pe, '#US')
        var_num = get_varient(string_list)
        print "  [-] Identify version"
        if var_num == 1:
            key, salt = 'EncryptedCredentials', '3000390039007500370038003700390037003800370038003600'.decode('hex')
            config_dict = config_1(key, salt, string_list)
        elif var_num == 2:
            key, salt = 'PredatorLogger', '3000390039007500370038003700390037003800370038003600'.decode('hex')
        print var_num
        
        return config_dict
        
        #raw_config = get_stream(pe)
        # Get a list of strings
        #string_list = parse_strings(raw_config)
        #parse the string list
        #config_dict = parse_config(string_list)
        #return config_dict

    
        
#Helper Functions Go Here

# Crypto Stuffs
def decrypt_string(key, salt, coded):
    #try:
        # Derive key
        generator = PBKDF2(key, salt)
        aes_iv = generator.read(16)
        aes_key = generator.read(32)
        # Crypto
        mode = AES.MODE_CBC
        cipher = AES.new(aes_key, mode, IV=aes_iv)
        value = cipher.decrypt(b64decode(coded)).replace('\x00', '')
        return value#.encode('hex')
    #except:
        #return False

# Get a list of strings from a section
def get_strings(pe, dir_type):
    counter = 0
    string_list = []
    m = pe.ntHeaders.optionalHeader.dataDirectory[14].info
    for s in m.netMetaDataStreams[dir_type].info:
        for offset, value in s.iteritems():
            string_list.append(value)
            #print value
        counter += 1
    return string_list
    
# Find varient
# This is hacky but im basing it off string locations. 
def get_varient(string_list):
    if string_list[18] .endswith('email'):
        return 1
    if string_list[13].endswith('email'):
        return 2
        
#Turn the strings in to a python config_dict
def config_1(key, salt, string_list):
    config_dict = {}
    #print decrypt_string(key, salt, string_list[4])
    config_dict["Email Address"] = decrypt_string(key, salt, string_list[4])
    config_dict["Email Password"] = decrypt_string(key, salt, string_list[5])
    config_dict["SMTP Server"] = decrypt_string(key, salt, string_list[6])
    config_dict["SMTP Port"] = string_list[7]
    config_dict["Interval Timer"] = string_list[8]
    config_dict["MsgBox String"] = string_list[9]
    config_dict["MsgBox Title"] = string_list[10]
    config_dict["MsgBox Type"] = string_list[11]
    config_dict["FTP Host"] = decrypt_string(key, salt, string_list[12])
    config_dict["FTP User"] = decrypt_string(key, salt, string_list[13])
    config_dict["FTP Pass"] = decrypt_string(key, salt, string_list[14])
    config_dict["PHP Link"] = decrypt_string(key, salt, string_list[15])
    config_dict["Use Email"] = string_list[18]
    config_dict["Use FTP"] = string_list[19]
    config_dict["Use PHP"] = string_list[20]
    config_dict["Delay Time"] = string_list[21]
    config_dict["Clear IE"] = string_list[22]
    config_dict["Clear FF"] = string_list[23]
    config_dict["Bind Files"] = 'This needs a test and export boudn files'
    config_dict["Download File"] = string_list[25]
    config_dict["Download Name"] = string_list[26]
    config_dict["Download link"] = string_list[27]
    return config_dict
        



#Recursive Function Goes Here


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
        print "[!] Config not found"
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
