#!/usr/bin/env python
'''
ShadowTech Rat Config Decoder
'''

__description__ = 'ShadowTech Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/08/23'

#Standard Imports Go Here
import os
import sys
import string
from optparse import OptionParser
from operator import xor


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

new_line = '#-@NewLine@-#'
split_string = 'ESILlzCwXBSrQ1Vb72t6bIXtKRzHJkolNNL94gD8hIi9FwLiiVlrznTz68mkaaJQQSxJfdLyE4jCnl5QJJWuPD4NeO4WFYURvmkth8' # 
enc_key = 'pSILlzCwXBSrQ1Vb72t6bIXtKRzAHJklNNL94gD8hIi9FwLiiVlr' # Actual key is 'KeY11PWD24'

def run(data):
    raw_config = get_config(data)
    return parse_config(raw_config)

        
#Helper Functions Go Here

def get_config(data):
    config_list = []
    config_string = data.split(split_string)
    for x in range(1, len(config_string)):
        output = ""
        hex_pairs = [config_string[x][i:i+2] for i in range(0, len(config_string[x]), 2)]
        for i in range(0,len(config_string[x])/2):
            data_slice = int(hex_pairs[i], 16)#get next hex value
            key_slice = ord(enc_key[i+1])#get next Char For Key
            output += chr(xor(data_slice,key_slice)) # xor Hex and Key Char
        config_list.append(output)
    return config_list

# Returns only printable chars
def string_print(line):
    return ''.join((char for char in line if 32 < ord(char) < 127))

# returns pretty config
def parse_config(config_list):
    config_dict = {}
    config_dict['Domain'] = config_list[0]
    config_dict['Port'] = config_list[1]
    config_dict['CampaignID'] = config_list[2]
    config_dict['Password'] = config_list[3]
    config_dict['InstallFlag'] = config_list[4]
    config_dict['RegistryKey'] = config_list[5]
    config_dict['Melt'] = config_list[6]
    config_dict['Persistance'] = config_list[7]
    config_dict['Mutex'] = config_list[8]
    config_dict['ShowMsgBox'] = config_list[9]
    #config_dict['Flag5'] = config_list[10] # MsgBox Icon
    #config_dict['Flag6'] = config_list[11] # MsgBox Buttons
    config_dict['MsgBoxTitle'] = config_list[12]
    config_dict['MsgBoxText'] = config_list[13]
    return config_dict

def decrypt_XOR(enckey, data):                    
    cipher = XOR.new(enckey) # set the cipher
    return cipher.decrypt(data) # decrpyt the data
    

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
