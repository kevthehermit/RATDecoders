#!/usr/bin/env python
'''
LostDoor Rat Config Decoder
'''


__description__ = 'LostDoor Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/06/04'

#Standard Imports Go Here
import os
import sys
import string
from optparse import OptionParser

#Non Standard Imports
try:
    from Crypto.Cipher import ARC4
except ImportError:
    print "[+] Couldn't Import PyCrypto. Try 'sudo pip install pycrypto'"


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python conf_dict of values
'''

def run(data):
    config = verDetect(data)
    if config:
        return config
    else:
        return config
    
#Helper Functions Go Here
####RC4 Cipher ####    
def DecryptRC4(enckey, data):
    cipher = ARC4.new(enckey) # set the ciper
    return cipher.decrypt(data.decode('hex')) # decrpyt the data

def verDetect(data):
    first = data.split("*EDIT_SERVER*")
    if len(first) == 2:
        second = first[1].split("\r\n")
        if len(second) > 14 < 30:
            print "[+] Found Version < 8"
            return new_decoder(second)
    first = data.split("[DATA]")
    if len(first) == 21:
        print "[+] Found Version 8"
        return v80(first)
    if len(first) == 30:
        print "[+] Found Version 8.01"
        return v801(first)
    return None
        

def new_decoder(split_list):
    raw_dict = {}
    for line in split_list:
        try:
            k,v = line.split(" = ")
            raw_dict[k[1:-1]] = v[1:-1]
        except:
            continue
    return config_cleaner(raw_dict)

def config_cleaner(raw_dict):
    clean_dict = {}
    for k,v in raw_dict.iteritems():
        if k == 'ip':
            clean_dict['Domain'] = DecryptRC4("oussamio", v)
        if k == 'fire':
            clean_dict['Firewall Bypass'] = v
        if k == 'foder':
            clean_dict['InstallPath'] = v
        if k == 'mlt':
            clean_dict['Melt'] = v
        if k == 'msns':
            clean_dict['MSN Spread'] = v
        if k == 'name':
            clean_dict['Reg Key'] = v
        if k == 'path':
            clean_dict['Reg value'] = v
        if k == 'port':
            clean_dict['Port'] = v
        if k == 'ppp':
            clean_dict['P2PSpread'] = v
        if k == 'reg':
            clean_dict['Registry Startup'] = v
        if k == 'usb':
            clean_dict['USB Spread'] = v
        if k == 'usbn':
            clean_dict['USB Name'] = v
        if k == 'victimo':
            clean_dict['CampaignID'] = v
    return clean_dict

def v80(conf):
    conf_dict = {}
    conf_dict["Domain"] = DecryptRC4("UniQue OussamiO", conf[1])
    conf_dict["Campaign"] = conf[2]
    conf_dict["Enable Startup"] = conf[3]
    conf_dict["StartupName"] = conf[4]
    conf_dict["FolderName"] = conf[5]
    if conf[6] == "D":
        conf_dict["Path"] = "App Data Folder"
    elif conf[6] == "W":
        conf_dict["Path"] = "Windows Folder"
    if conf[6] == "s":
        conf_dict["Path"] = "System Folder"
    conf_dict["Enable Error Message"] = conf[7]
    conf_dict["Error Message"] = conf[8]
    conf_dict["Disable Firewall"] = conf[9]
    #conf_dict[""] = conf[10]
    #conf_dict[""] = conf[11]
    conf_dict["USB Spread"] = conf[12]
    conf_dict["MSN Spread"] = conf[13]
    conf_dict["P2P Spread"] = conf[14]
    conf_dict["Melt"] = conf[15]
    conf_dict["Get Default User Name"] = conf[16]
    conf_dict["Connection Delay"] = conf[17]
    conf_dict["Set Hidden"] = conf[18]
    conf_dict["Protect Process"] = conf[19]
    #conf_dict[""] = conf[20]

    return conf_dict
    
def v801(conf):
    conf_dict = {}
    conf_dict["Domain"] = DecryptRC4("UniQue OussamiO", conf[1])
    conf_dict["Campaign"] = conf[2]
    conf_dict["Enable Startup"] = conf[3]
    conf_dict["StartupName"] = conf[4]
    conf_dict["FolderName"] = conf[5]
    if conf[6] == "D":
        conf_dict["Path"] = "App Data Folder"
    elif conf[6] == "W":
        conf_dict["Path"] = "Windows Folder"
    if conf[6] == "s":
        conf_dict["Path"] = "System Folder"
    conf_dict["Enable Error Message"] = conf[7]
    conf_dict["Error Message"] = conf[8]
    conf_dict["Disable Firewall"] = conf[9]
    #conf_dict[""] = conf[10]
    #conf_dict[""] = conf[11]
    conf_dict["USB Spread"] = conf[12]
    conf_dict["MSN Spread"] = conf[13]
    conf_dict["P2P Spread"] = conf[14]
    conf_dict["Melt"] = conf[15]
    conf_dict["Get Default User Name"] = conf[16]
    conf_dict["Connection Delay"] = conf[17]
    conf_dict["Set Hidden"] = conf[18]
    conf_dict["Protect Process"] = conf[19]
    conf_dict["Name To Spread"] = conf[20]
    conf_dict["Enable Active X"] = conf[21]
    conf_dict["Active X Key"] = conf[22]
    conf_dict["Enable Mutex"] = conf[23]
    conf_dict["Mutex"] = conf[24]
    conf_dict["Persistant Server"] = conf[25]
    conf_dict["Offline Keylogger"] = conf[26]
    conf_dict["Disable Task Manager"] = conf[27]
    conf_dict["Disable RegEdit"] = conf[28]
    return conf_dict


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
