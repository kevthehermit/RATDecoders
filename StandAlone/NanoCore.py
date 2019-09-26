#!/usr/bin/env python
'''
NanoCore Rat Config Decoder
'''

__description__ = 'NanoCoreRat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.3'
__date__ = '2015/04'

#Standard Imports Go Here
import os
import re
import sys
import zlib
import string
from struct import unpack
from optparse import OptionParser
import uuid

#Non Standard Imports
from Crypto.Cipher import DES, AES
import pefile

# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(raw_data):
    try:
        coded_config = get_codedconfig(raw_data)
        if coded_config[0:4] == '\x08\x00\x00\x00':
            print "    [-] Found version 1.1x"
            config_dict = decrypt_v2(coded_config)
            
        elif coded_config[0:4] == '\x10\x00\x00\x00':
            print "    [-] Found Version 2.x"
            # we need to derive a key from teh assembly guid
            guid = re.search('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', raw_data).group()
            guid = uuid.UUID(guid).bytes_le
            encrypted_key = coded_config[4:20]
            # rfc2898 derive bytes
            derived_key = derive_key(guid, encrypted_key)
            config_dict = decrypt_v3(coded_config, derived_key)
        else:
           print "    [-] Found Version 1.0x"
           config_dict = decrypt_v1(coded_config)
        return config_dict
    except:
        return

#Helper Functions Go Here

def derive_key(guid, coded_key):
    try:
        from pbkdf2 import PBKDF2
    except:
        print "[!] Unable to derive a key. requires 'sudo pip install pbkdf2'"
        sys.exit()
    generator = PBKDF2(guid, guid, 8)
    aes_iv = generator.read(16)
    aes_key = generator.read(16)
    derived_key = decrypt_aes(aes_key, aes_iv, coded_key)
    return derived_key

def decrypt_v3(coded_config, key):
    data = coded_config[24:]
    raw_config = decrypt_des(key[:8], data)
    # if the config is over a certain size it is compressed. Indicated by a non Null byte
    if raw_config[1] == '\x00':
        return parse_config(raw_config, '3')
    else:
        # remove the string lengths and deflate the remainder of the stream
        deflate_config = deflate_contents(raw_config)
        with open('nano_2.res', 'wb') as out:
            out.write(deflate_config)
        return parse_config(deflate_config, '3')

def decrypt_v2(coded_config):
    key = coded_config[4:12]
    data = coded_config[16:]
    raw_config = decrypt_des(key, data)
    # if the config is over a certain size it is compressed. Indicated by a non Null byte
    if raw_config[1] == '\x00':
        return parse_config(raw_config, '2')
    else:
        # remove the string lengths and deflate the remainder of the stream
        deflate_config = deflate_contents(raw_config)
        return parse_config(deflate_config, '2')
            
def decrypt_v1(coded_config):
    key = '\x01\x03\x05\x08\x0d\x15\x22\x37'
    data = coded_config[1:]
    new_data = decrypt_des(key, data)
    if new_data[0] != '\x00':
        deflate_config = deflate_contents(new_data)
        return parse_config(deflate_config, 'old')

def deflate_contents(data):
    new_data = data[5:]
    return zlib.decompress(new_data, -15)

# Returns only printable chars
def string_print(line):
    try:
        return ''.join((char for char in line if 32 < ord(char) < 127))
    except:
        return line

# returns pretty config
def parse_config(raw_config, ver):
    config_dict = {}
    
    # Some plugins drop in here as exe files. 
    if 'This program cannot be run' in raw_config:
        print '    [!] Embedded EXE Plugin found'
        raw_config = raw_config.split('BuildTime')[1]
    with open('split.bin', 'wb') as out:
        out.write(raw_config)
    
    if ver == '2':
        #config_dict['BuildTime'] = unpack(">Q", re.search('BuildTime(.*?)\x0c', raw_config).group()[10:-1])[0]
        config_dict['Version'] = re.search('Version\x0c(.*?)\x0c', raw_config).group()[8:-1]
        config_dict['Mutex'] = re.search('Mutex(.*?)\x0c', raw_config).group()[6:-1].encode('hex')
        config_dict['Group'] = re.search('DefaultGroup\x0c(.*?)\x0c', raw_config).group()[14:-1]
        config_dict['Domain1'] = re.search('PrimaryConnectionHost\x0c(.*?)Back', raw_config, re.DOTALL).group()[23:-6]
        config_dict['Domain2'] = re.search('BackupConnectionHost\x0c(.*?)\x0c', raw_config).group()[22:-1]
        config_dict['Port'] = unpack("<H", re.search('ConnectionPort...', raw_config, re.DOTALL).group()[15:])[0]
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
    elif ver == '3':
        config_dict['Version'] = re.search('Version..(.*?)\x0c', raw_config).group()[8:16]
        config_dict['Mutex'] = re.search('Mutex(.*?)\x0c', raw_config).group()[6:-1].encode('hex')
        config_dict['Group'] = re.search('DefaultGroup\x0c(.*?)\x0c', raw_config).group()[14:-1]
        config_dict['Domain1'] = re.search('PrimaryConnectionHost\x0c(.*?)Back', raw_config, re.DOTALL).group()[23:-6]
        config_dict['Domain2'] = re.search('BackupConnectionHost\x0c(.*?)\x0c', raw_config).group()[22:-1]
        config_dict['Port'] = unpack("<H", re.search('ConnectionPort...', raw_config, re.DOTALL).group()[15:])[0]
        config_dict['RunOnStartup'] = re.search('RunOnStartup(.*?)\x0c', raw_config).group()[13:-1].encode('hex')
        config_dict['RequestElevation'] = re.search('RequestElevation(.*?)\x0c', raw_config).group()[17:-1].encode('hex')
        config_dict['BypassUAC'] = re.search('BypassUserAccountControl(.*?)\x0c', raw_config).group()[25:-1].encode('hex')
        config_dict['ClearZoneIdentifier'] = re.search('ClearZoneIdentifier(.*?)\x0c', raw_config).group()[20:-1].encode('hex')
        config_dict['ClearAccessControl'] = re.search('ClearAccessControl(.*?)\x0c', raw_config).group()[19:-1].encode('hex')
        config_dict['SetCriticalProcess'] = re.search('SetCriticalProcess(.*?)\x0c', raw_config).group()[19:-1].encode('hex')
        config_dict['PreventSystemSleep'] = re.search('PreventSystemSleep(.*?)\x0c', raw_config).group()[19:-1].encode('hex')

        config_dict['EnableDebugMode'] = re.search('EnableDebugMode(.*?)\x0c', raw_config).group()[16:-1].encode('hex')
        config_dict['ConnectDelay'] = unpack("<i", re.search('ConnectDelay(.*?)\x0c', raw_config).group()[13:-1])[0]
        config_dict['RestartDelay'] = unpack("<i", re.search('RestartDelay(.*?)\x0c', raw_config).group()[13:-1])[0]
        try:
            config_dict['UseCustomDNS'] = re.search('UseCustomDnsServer(.*?)\x0c', raw_config).group()[19:-1].encode('hex')
            config_dict['PrimaryDNSServer'] = re.search('PrimaryDnsServer\x0c(.*?)\x0c', raw_config).group()[18:-1]
            config_dict['BackupDNSServer'] = re.search('BackupDnsServer\x0c(.*?)(\x04|\x0c)', raw_config).group()[16:-1]
        except:
            pass

    else:
        config_dict['Domain'] = re.search('HOST\x0c(.*?)\x0c', raw_config).group()[6:-1]
        config_dict['Port'] = unpack("<H", re.search('PORT(.*?)\x0c', raw_config).group()[5:-1])[0]
        config_dict['Group'] = re.search('GROUP\x0c(.*?)\x0c', raw_config).group()[7:-1]
        config_dict['ConnectDelay'] = unpack("<i", re.search('DELAY(.*?)\x0c', raw_config).group()[6:-1])[0]
        config_dict['OfflineKeyLog'] = str(re.search('OFFLINE_KEYLOGGING(.*?)\x0c', raw_config).group()[19:-1].encode('hex'))
    return config_dict

# This gets the encoded config from a stub
def get_codedconfig(data):
    coded_config = None
    pe = pefile.PE(data=data)
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(entry.name) in ("RC_DATA", "RCData"):
            new_dirs = entry.directory
            for res in new_dirs.entries:
                data_rva = res.directory.entries[0].data.struct.OffsetToData
                size = res.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                coded_config = data
                # Icons can get in the way. 
                if coded_config.startswith('\x28\x00\x00'):
                    break
                return coded_config

def decrypt_des(key, data):
    iv = key
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(data)
    
def decrypt_aes(key, iv, data):
    mode = AES.MODE_CBC
    cipher = AES.new(key, mode, IV=iv)
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
