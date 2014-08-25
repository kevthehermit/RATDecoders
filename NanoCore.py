#!/usr/bin/env python
'''
NanoCore Rat Config Decoder
'''


__description__ = 'xRat Rat Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/09/25'

#Standard Imports Go Here
import os
import re
import sys
import zlib
import string
from struct import unpack
from optparse import OptionParser



#Non Standard Imports
from Crypto.Cipher import DES
import pefile

# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(raw_data):
    try:
        coded_config = get_codedconfig(raw_data)
        key = coded_config[4:12]
        data = coded_config[16:]
        raw_config = decrypt_des(key, data)
        # if the config is over a certain size it is compressed. Indicated by a non Null byte
        if raw_config[1] == '\x00':
            return parse_config(raw_config)
        else:
            # remove the string lengths and deflate the remainder of the stream
            deflate_string = raw_config[5:]
            deflate_config = zlib.decompress(deflate_string, -15)
            return parse_config(deflate_config)
    except:
        return

#Helper Functions Go Here

# Returns only printable chars
def string_print(line):
    try:
        return ''.join((char for char in line if 32 < ord(char) < 127))
    except:
        return line

# returns pretty config
def parse_config(raw_config):
    config_dict = {}
    #config_dict['BuildTime'] = unpack(">Q", re.search('BuildTime(.*?)\x0c', raw_config).group()[10:-1])[0]
    config_dict['Version'] = re.search('Version\x0c(.*?)\x0c', raw_config).group()[8:-1]
    config_dict['Mutex'] = re.search('Mutex(.*?)\x0c', raw_config).group()[6:-1].encode('hex')
    config_dict['Group'] = re.search('DefaultGroup\x0c(.*?)\x0c', raw_config).group()[14:-1]
    config_dict['Domain1'] = re.search('PrimaryConnectionHost\x0c(.*?)\x0c', raw_config).group()[23:-1]
    config_dict['Domain2'] = re.search('BackupConnectionHost\x0c(.*?)\x0c', raw_config).group()[22:-1]
    config_dict['Port'] = unpack("<H", re.search('ConnectionPort(.*?)\x0c', raw_config).group()[15:-1])[0]
    config_dict['RunOnStartup'] = re.search('RunOnStartup(.*?)\x0c', raw_config).group()[13:-1].encode('hex')
    config_dict['RequestElevation'] = re.search('RequestElevation(.*?)\x0c', raw_config).group()[17:-1].encode('hex')
    config_dict['BypassUAC'] = re.search('BypassUserAccountControl(.*?)\x0c', raw_config).group()[25:-1].encode('hex')
    config_dict['ClearZoneIdentifier'] = re.search('ClearZoneIdentifier(.*?)\x0c', raw_config).group()[20:-1].encode('hex')
    config_dict['ClearAccessControl'] = re.search('ClearAccessControl(.*?)\x0c', raw_config).group()[19:-1].encode('hex')
    config_dict['SetCriticalProcess'] = re.search('SetCriticalProcess(.*?)\x0c', raw_config).group()[19:-1].encode('hex')
    config_dict['FindLanServers'] = re.search('FindLanServers(.*?)\x0c', raw_config).group()[15:-1].encode('hex')
    config_dict['RestartOnException'] = re.search('RestartOnException(.*?)\x0c', raw_config).group()[19:-1].encode('hex')
    config_dict['EnableDebugMode'] = re.search('EnableDebugMode(.*?)\x0c', raw_config).group()[16:-1].encode('hex')
    config_dict['ConnectDelay'] = unpack("<i", re.search('ConnectDelay(.*?)\x0c', raw_config).group()[13:-1])[0]
    config_dict['RestartDelay'] = unpack("<i", re.search('RestartDelay(.*?)\x0c', raw_config).group()[13:-1])[0]
    #config_dict['TimeoutInterval'] = unpack("<i", re.search('TimeoutInterval(.*?)\x0c', raw_config).group()[16:-1])[0]
    #config_dict['KeepAliveTimeout'] = unpack("<i", re.search('KeepAliveTimeout(.*?)\x0c', raw_config).group()[17:-1])[0]
    #config_dict['MutexTimeout'] = unpack("<i", re.search('MutexTimeout(.*?)\x0c', raw_config).group()[13:-1])[0]
    #config_dict['LanTimeout'] = unpack("<i", re.search('LanTimeout(.*?)\x0c', raw_config).group()[11:-1])[0]
    #config_dict['WanTimeout'] = unpack("<i", re.search('WanTimeout(.*?)\x0c', raw_config).group()[11:-1])[0]
    #config_dict['BufferSize'] = unpack("<i", re.search('BufferSize(.*?)\x0c', raw_config).group()[11:-1])[0]
    #config_dict['MaxPacketSize'] = unpack("<i", re.search('MaxPacketSize(.*?)\x0c', raw_config).group()[14:-1])[0]
    return config_dict


# This gets the encoded config from a stub
def get_codedconfig(data):

    coded_config = None
    pe = pefile.PE(data=data)
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(entry.name) == "RC_DATA" or "RCData":
            new_dirs = entry.directory
            for res in new_dirs.entries:
                data_rva = res.directory.entries[0].data.struct.OffsetToData
                size = res.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                coded_config = data
                return coded_config

def decrypt_des(key, data):
    iv = key
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(data)

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
                outFile.write("Key: {0}\t Value: {1}\n".format(key,value))
    # if no seconds arg then assume you want it printing to screen
    else:
        print "[+] Printing Config to screen"
        for key, value in sorted(config.iteritems()):
            print "   [-] Key: {0}\t Value: {1}".format(key,value)
        print "[+] End of Config"
