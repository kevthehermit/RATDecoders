#!/usr/bin/env python
'''
Greame Rat Config Decoder
'''


__description__ = 'Greame Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/04/10'

#Standard Imports Go Here
import os
import sys
import string
from optparse import OptionParser

#Non Standard Imports
try:
    import pefile
except ImportError:
    print "[+] Couldn't Import pefile. Try 'sudo pip install pefile'"


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
    config_dict = {}
    config = get_config(data)
    if config:
        domains = config[0]
        dom_list = domains.split('****')
        if len(dom_list) > 1:
            counter = 0
            for dom in dom_list:
                if dom != '':
                    config_dict["Domain{0}".format(counter)] = dom
                    counter += 1
        config_dict["Port"] = config[1]
        config_dict["Password"] = config[2]
        config_dict["Install Folder"] = config[3]
        config_dict["Install Name"] = config[4]
        config_dict["HKCU Key"] = config[5]
        config_dict["ActiveX Key"] = config[6]
        config_dict["Install Flag"] = config[7]
        config_dict["Startup Flag"] = config[8]
        config_dict["ActiveX Startup"] = config[9]
        config_dict["HKCU Startup"] = config[10]
        config_dict["Mutex"] = config[11]
        config_dict["UserMode UnHooking"] = config[12]
        config_dict["Melt"] = config[13]
        config_dict["Active Keylogger"] = config[14]
        config_dict["Remote-PC"] = config[15]
        config_dict["Enable RootKit"] = config[16]
        config_dict["Thread Persistence"] = config[17]
        config_dict["Anti Sandbox"] = config[18]
        config_dict["Anti VM"] = config[19]
        return config_dict
    else:
        return False
    
        
#Helper Functions Go Here
def get_config(raw_data):
    try:
        pe = pefile.PE(data=raw_data)
        rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "CFG":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                config = data.split('##')
                return config
    except:
        return None

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
