#!/usr/bin/env python
'''
Predator Pain
'''

__description__ = 'Predator Logger Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.2'
__date__ = '2015/06/13'

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
        string_list = get_strings(pe, 2)
        print "  [+] Identify version"
        vers = get_version(string_list)
        
        if vers == 'v12':
            config_dict = config_12(string_list)
        elif vers == 'v13':
            key, salt = 'PredatorLogger', '3000390039007500370038003700390037003800370038003600'.decode('hex')
            config_dict = config_13(key, salt, string_list)
        elif vers == 'v14':
            key, salt = 'EncryptedCredentials', '3000390039007500370038003700390037003800370038003600'.decode('hex')
            config_dict = config_14(key, salt, string_list)
        else:   
            return
        return config_dict

        
#Helper Functions Go Here

def string_clean(line):
    return ''.join((char for char in line if 32< ord(char) < 127))
    
# Crypto Stuffs
def decrypt_string(key, salt, coded):
    #try:
        print coded
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
            #print counter, value
        counter += 1
    return string_list
    
# Find Version
def get_version(string_list):
    # Pred v12
    if 'Predator Pain v12 - Server Ran - [' in string_list:
        print "    [-] Found Predator Pain v12"
        return 'v12'
    # Pred v13
    elif 'Predator Pain v13 - Server Ran - [' in string_list:
        print "    [-] Found Predator Pain v13"
        return 'v13'
    # Pred v14
    elif 'EncryptedCredentials' in string_list:
        print "    [-] Found Predator Pain v14"
        return 'v14'
    else:
        return


        
def config_12(string_list):
    config_dict = {}
    config_dict["Version"] = "Predator Pain v12"
    config_dict["Email Address"] = string_list[4]
    config_dict["Email Password"] = string_list[5]
    config_dict["SMTP Server"] = string_list[6]
    config_dict["SMTP Port"] = string_list[7]
    config_dict["Interval Timer"] = string_list[8]
    if string_list[9].startswith('ReplaceBind'):
        config_dict['BindFile1'] = 'False'
    else:
        config_dict['BindFile1'] = 'True'
    
    if string_list[10].startswith('ReplaceBind'):
        config_dict['BindFile2'] = 'False'
    else:
        config_dict['BindFile2'] = 'True'
    return config_dict

#Turn the strings in to a python config_dict
def config_13(key, salt, string_list):
    '''
    Identical Strings are not stored multiple times. 
    We need to check for duplicate passwords which mess up the positionl arguemnts.
    '''
    
    if 'email' in string_list[13]:
        dup = True
    elif 'email' in string_list[14]:
        dup = False
    
    config_dict = {}
    config_dict["Version"] = "Predator Pain v13"
    config_dict["Email Address"] = decrypt_string(key, salt, string_list[4])
    config_dict["Email Password"] = decrypt_string(key, salt, string_list[5])
    config_dict["SMTP Server"] = decrypt_string(key, salt, string_list[6])
    config_dict["SMTP Port"] = string_list[7]
    config_dict["Interval Timer"] = string_list[8]
    config_dict["FTP Host"] = decrypt_string(key, salt, string_list[10])
    config_dict["FTP User"] = decrypt_string(key, salt, string_list[11])
    if dup:
        config_dict["FTP Pass"] = decrypt_string(key, salt, string_list[5])
        config_dict["PHP Link"] = decrypt_string(key, salt, string_list[12])
        config_dict["Use Email"] = string_list[13]
        config_dict["Use FTP"] = string_list[14]
        config_dict["Use PHP"] = string_list[15]
        config_dict["Download & Exec"] = string_list[20]
        if string_list[19] == 'bindfiles':
            config_dict["Bound Files"] = 'False'
        else:
            config_dict["Bound Files"] = 'True'
    else:
        config_dict["FTP Pass"] = decrypt_string(key, salt, string_list[12])
        config_dict["PHP Link"] = decrypt_string(key, salt, string_list[13])
        config_dict["Use Email"] = string_list[14]
        config_dict["Use FTP"] = string_list[15]
        config_dict["Use PHP"] = string_list[16]
        config_dict["Download & Exec"] = string_list[21]
        if string_list[20] == 'bindfiles':
            config_dict["Bound Files"] = 'False'
        else:
            config_dict["Bound Files"] = 'True'
    return config_dict
        
#Turn the strings in to a python config_dict
def config_14(key, salt, string_list):
    '''
    Identical Strings are not stored multiple times. 
    possible pass and date dupes make it harder to test
    '''

    # date Duplicate
    if 'email' in string_list[18]:
        dup = True
    elif 'email' in string_list[19]:
        dup = False
    
    
    
    config_dict = {}
    config_dict["Version"] = "Predator Pain v14"
    config_dict["Email Address"] = decrypt_string(key, salt, string_list[4])
    config_dict["Email Password"] = decrypt_string(key, salt, string_list[5])
    config_dict["SMTP Server"] = decrypt_string(key, salt, string_list[6])
    config_dict["SMTP Port"] = string_list[7]
    config_dict["Interval Timer"] = string_list[8]
    config_dict["FTP Host"] = decrypt_string(key, salt, string_list[12])
    config_dict["FTP User"] = decrypt_string(key, salt, string_list[13])
    config_dict["FTP Pass"] = decrypt_string(key, salt, string_list[14])
    config_dict["PHP Link"] = decrypt_string(key, salt, string_list[15])
    if dup:
        config_dict["PHP Link"] = decrypt_string(key, salt, string_list[15])
        config_dict["Use Email"] = string_list[18]
        config_dict["Use FTP"] = string_list[19]
        config_dict["Use PHP"] = string_list[20]
        config_dict["Download & Exec"] = string_list[25]
        if string_list[24] == 'bindfiles':
            config_dict["Bound Files"] = 'False'
        else:
            config_dict["Bound Files"] = 'True'
    else:
        config_dict["Use Email"] = string_list[19]
        config_dict["Use FTP"] = string_list[20]
        config_dict["Use PHP"] = string_list[21]
        config_dict["Download & Exec"] = string_list[26]
        if string_list[25] == 'bindfiles':
            config_dict["Bound Files"] = 'False'
        else:
            config_dict["Bound Files"] = 'True'
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

    try:
        print "[+] Reading file"
        fileData = open(args[0], 'rb').read()
    except:
        print "[+] Couldn't Open File {0}".format(args[0])
    #Run the config extraction
    print "[+] Searching for Config"
    config = run(fileData)
    #If we have a config figure out where to dump it out.
    if not config:
        print "[!] Config not found"
        sys.exit()
    #if you gave me two args im going to assume the 2nd arg is where you want to save the file
    if len(args) == 2:
        print "[+] Writing Config to file {0}".format(args[1])
        with open(args[1], 'a') as outFile:
            for key, value in sorted(config.iteritems()):
                clean_value = string_clean(value)
                outFile.write("Key: {0}\t Value: {1}\n".format(key,clean_value))
    # if no seconds arg then assume you want it printing to screen
    else:
        print "[+] Printing Config to screen"
        for key, value in sorted(config.iteritems()):
            clean_value = string_clean(value)
            print "   [-] Key: {0}\t Value: {1}".format(key,clean_value)
        print "[+] End of Config"
