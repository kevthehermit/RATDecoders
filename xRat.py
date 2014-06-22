#!/usr/bin/env python
'''
xRat Rat Rat Config Decoder
'''


__description__ = 'xRat Rat Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/06/17'

#Standard Imports Go Here
import os
import sys
import string
from optparse import OptionParser
from base64 import b64decode
import hashlib
import re

#Non Standard Imports
from Crypto.Cipher import AES, XOR
import pefile

# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
    long_line, ver = get_long_line(data)
    if ver == None:
        return None
    config_list = []
    if ver == 'V1':
        print "[+] Found Version 1.x"
        # The way the XOR Cypher was implemented the keys are off by 1. 
        key1 = 'RAT11x' # Used for First level of encryption actual key is 'xRAT11'
        key2 = 'eY11K' # used for individual sections, actual key is 'KeY11'
        key3 = 'eY11PWD24K' # used for password section only. Actual key is 'KeY11PWD24'
        config = long_line.decode('hex')
        first_decode = decrypt_XOR(key1, config)
        sections = first_decode.split('|//\\\\|') # Split is |//\\| the extra \\ are for escaping.
        for i in range(len(sections)):
            if i == 3:
                enc_key = key3
            else:
                enc_key = key2
            config_list.append(decrypt_XOR(enc_key, sections[i].decode('hex')))
    if ver == 'V2':
        print "[+] Found Version 2.x"
        coded_lines = get_parts(long_line)
        enc_key = aes_key(coded_lines[-1])
        for i in range(1, (len(coded_lines)-1)):
            decoded_line = b64decode(coded_lines[i])
            decrypt_line = decrypt_aes(enc_key, decoded_line)
            config_list.append(string_print(decrypt_line))
    return parse_config(config_list, ver)
        
#Helper Functions Go Here




# Returns only printable chars
def string_print(line):
    return ''.join((char for char in line if 32 < ord(char) < 127))

# returns pretty config
def parse_config(config_list, ver):
    config_dict = {}
    if ver == 'V1':
        config_dict['Version'] = '1.0.x'
        config_dict['Domain'] = config_list[1]
        config_dict['Port'] = config_list[2]
        config_dict['Password'] = config_list[3]
        config_dict['CampaignID'] = config_list[4]
        config_dict['InstallName'] = config_list[5]
        config_dict['HKCUKey'] = config_list[6]
        config_dict['InstallDir'] = config_list[7]
        config_dict['Flag1'] = config_list[8]
        config_dict['Flag2'] = config_list[9]
        config_dict['Mutex'] = config_list[10]
        
        
    if ver == 'V2':
        config_dict['Version'] = config_list[0]
        config_dict['Domain'] = config_list[1]
        config_dict['Password'] = config_list[2]
        config_dict['InstallSub'] = config_list[3]
        config_dict['InstallName'] = config_list[4]
        config_dict['Mutex'] = config_list[5]
        config_dict['RegistryKey'] = config_list[6]
    return config_dict



# This gets the encoded config from a stub
def get_long_line(data):
    try:
        raw_config = None
        pe = pefile.PE(data=data)
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if str(entry.name) == "RT_RCDATA":
                new_dirs = entry.directory
                for entry in new_dirs.entries:
                    if str(entry.name) == '0':
                        data_rva = entry.directory.entries[0].data.struct.OffsetToData
                        size = entry.directory.entries[0].data.struct.Size
                        data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                        raw_config = data
    except:
        raw_config = None

    if raw_config != None:
        return raw_config, 'V1'
    try:
        m = re.search('\x69\x00\x6F\x00\x6E\x00\x00\x59(.*)\x6F\x43\x00\x61\x00\x6E', data)
        raw_config = m.group(0)[4:-12]
        return raw_config, 'V2'
    except:
        return None, None

##################
# These are for V1
#

def decrypt_XOR(enckey, data):                    
    cipher = XOR.new(enckey) # set the cipher
    return cipher.decrypt(data) # decrpyt the data
    
##################
# These are for V2
#

# decrypt function
def decrypt_aes(enckey, data):
    iv = data[:16]
    cipher = AES.new(enckey, AES.MODE_CBC, iv) # set the cipher
    return cipher.decrypt(data[16:]) # decrpyt the data

# converts the enc key to an md5 key
def aes_key(enc_key):
    return hashlib.md5(enc_key).hexdigest().decode('hex')

# This will split all the b64 encoded strings and the encryption key
def get_parts(long_line):
    coded_config = []
    raw_line = long_line
    small_lines = raw_line.split('\x00\x00')
    for line in small_lines:
        if len(line) % 2 == 0:
            new_line = line[1:]
        else:
            new_line = line[2:]
        coded_config.append(new_line.replace('\x00',''))
    return coded_config


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
                clean_value = filter(lambda x: x in string.printable, value)
                outFile.write("Key: {0}\t Value: {1}\n".format(key,clean_value))
    # if no seconds arg then assume you want it printing to screen
    else:
        print "[+] Printing Config to screen"
        for key, value in sorted(config.iteritems()):
            clean_value = filter(lambda x: x in string.printable, value)
            print "   [-] Key: {0}\t Value: {1}".format(key,clean_value)
        print "[+] End of Config"
