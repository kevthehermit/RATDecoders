#!/usr/bin/env python
'''
jRAT Rat Config Decoder
'''


__description__ = 'jRAT Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.3'
__date__ = '2015/04/03'

#Standard Imports Go Here
import os
import sys
from base64 import b64decode
import string
from zipfile import ZipFile
from optparse import OptionParser
from cStringIO import StringIO

#Non Standard Imports
try:
    from Crypto.Cipher import AES, DES3
except ImportError:
    print "[+] Couldn't Import Cipher, try 'sudo pip install pycrypto'"


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
    print "[+] Extracting Data from Jar"
    enckey, conf = get_parts(data)
    if enckey == None:
        return
    print "[+] Decoding Config with Key: {0}".format(enckey.encode('hex'))
    if len(enckey) == 16:
        # Newer versions use a base64 encoded config.dat
        if '==' in conf: # this is not a great test but should work 99% of the time
            b64_check = True
        else:
            b64_check = False
        if b64_check:
            raw_config = new_aes(conf, enckey)
        else:
            raw_config = old_aes(conf, enckey)
    if len(enckey) in [24, 32]:
        raw_config = old_des(conf, enckey)
    config_dict = parse_config(raw_config, enckey)
    return config_dict



#Helper Functions Go Here

# This extracts the Encryption Key and Config File from the Jar and or Dropper
def get_parts(data):
    new_zip = StringIO(data)
    enckey = None
    dropper = None
    conf = None
    try:
        with ZipFile(new_zip, 'r') as zip:
            for name in zip.namelist(): # get all the file names
                if name == "key.dat": # this file contains the encrytpion key
                    enckey = zip.read(name)
                if name == "enc.dat": # if this file exists, jrat has an installer / dropper                
                    dropper = zip.read(name)
                if name == "config.dat": # this is the encrypted config file
                    conf = zip.read(name)
    except:
        print "[+] Dropped File is not Jar File starts with Hex Chars: {0}".format(data[:5].encode('hex'))
        return None, None
    if enckey and conf:
        return enckey, conf
    elif enckey and dropper:
        newkey, conf = get_dropper(enckey, dropper)
        return newkey, conf
    else:
        return None, None


# This extracts the Encryption Key and New conf from a 'Dropper' jar
def get_dropper(enckey, dropper):
    try:
        split = enckey.split('\x2c')
        key = split[0][:16]
        print "[+] Dropper Detected"
        for x in split: # grab each line of the config and decode it.
            try:
                drop = b64decode(x).decode('hex')
                print "    [-] {0}".format(drop).replace('\x0d\x0a','')
            except:
                drop = b64decode(x[16:]).decode('hex')
                print "    [-] {0}".format(drop)
        new_zipdata = decrypt_aes(key, dropper)
        new_key, conf = get_parts(new_zipdata)
        return new_key, conf
    except:
        return None, None
    
    
# Returns only printable chars
def string_print(line):
    return ''.join((char for char in line if 32 < ord(char) < 127))

# Messy Messy Messy
def messy_split(long_line):
    # this is a messy way to split the data but it works for now.
    '''
    Split on = gives me the right sections but deletes the b64 padding
    use modulo math to restore padding.
    return new list.
    '''
    new_list = []
    old_list = long_line.split('=')
    for line in old_list:
        if len(line) != 0:
            line += "=" * ((4 - len(line) % 4) % 4)
            new_list.append(line)
    return new_list

# AES Decrypt
def decrypt_aes(enckey, data):                    
        cipher = AES.new(enckey) # set the cipher
        return cipher.decrypt(data) # decrpyt the data
        
# DES Decrypt
def decrypt_des(enckey, data):
        cipher = DES3.new(enckey) # set the ciper
        return cipher.decrypt(data) # decrpyt the data

# Process Versions 3.2.2 > 4.2.
def old_aes(conf, enckey):
    decoded_config = decrypt_aes(enckey, conf)
    clean_config = string_print(decoded_config)
    raw_config = clean_config.split('SPLIT')
    return raw_config
    
#Process versions 4.2. > 
def new_aes(conf, enckey):
    sections = messy_split(conf)
    decoded_config = ''
    for x in sections:
        decoded_config += decrypt_aes(enckey, b64decode(x))
    raw_config = string_print(decoded_config).split('SPLIT')
    return raw_config
    
# process versions < 3.2.2
def old_des(conf, enckey):
    decoded_config = decrypt_des(enckey, conf)
    clean_config = string_print(decoded_config)
    raw_config = clean_config.split('SPLIT')
    return raw_config
    
def parse_config(raw_config, enckey):
    config_dict = {}
    for kv in raw_config:
        if kv == '':
            continue
        kv = string_print(kv)
        key, value = kv.split('=')
        if key == 'ip':
            config_dict['Domain'] = value
        if key == 'addresses':
            dom_list = value.split(',')
            dom_count = 0
            for dom in dom_list:
                if dom == '':
                    continue
                config_dict['Domain {0}'.format(dom_count)] = value.split(':')[0]
                config_dict['Port {0}'.format(dom_count)] = value.split(':')[1]
                dom_count += 1
        if key == 'port':
            config_dict['Port'] = value
        if key == 'os':
            config_dict['OS'] = value
        if key == 'mport':
            config_dict['MPort'] = value
        if key == 'perms':
            config_dict['Perms'] = value
        if key == 'error':
            config_dict['Error'] = value
        if key == 'reconsec':
            config_dict['RetryInterval'] = value
        if key == 'ti':
            config_dict['TI'] = value
        if key == 'pass':
            config_dict['Password'] = value
        if key == 'id':
            config_dict['CampaignID'] = value
        if key == 'mutex':
            config_dict['Mutex'] = value
        if key == 'toms':
            config_dict['TimeOut'] = value
        if key == 'per':
            config_dict['Persistance'] = value
        if key == 'name':
            config_dict['InstallName'] = value
        if key == 'tiemout':
            config_dict['TimeOutFlag'] = value
        if key == 'debugmsg':
            config_dict['DebugMsg'] = value
    config_dict["EncryptionKey"] = enckey.encode('hex')
    return config_dict

#Recursive Function Goes Here

def runRecursive(folder, output):
    counter1 = 0
    counter2 = 0
    print "[+] Writing Configs to File {0}".format(output)
    with open(output, 'a+') as out:
        #This line will need changing per Decoder
        out.write("Filename,CampaignID,Domain,Port,OS,MPort,Perms,Error,RetryInterval,TI,Password,Mutex,TimeOut,Persistance,InstallName,TimeOutFlag,DebugMsg,EncryptionKey\n")    
        for server in os.listdir(folder):
            if os.path.isfile(os.path.join(folder, server)):
                print "[+] Processing File {0}".format(server)
                fileData = open(os.path.join(folder,server), 'rb').read()
                configOut = run(fileData)
                if configOut != None:
                    configOut["TimeOutFlag"] = ''
                    #This line will need changing per Decoder
                    out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17}\n'.format(server,configOut["CampaignID"],configOut["Domain"],configOut["Port"],configOut["OS"],configOut["MPort"],configOut["Perms"],configOut["Error"],configOut["RetryInterval"],configOut["TI"],configOut["Password"],configOut["Mutex"],configOut["TimeOut"],configOut["Persistance"],configOut["InstallName"],configOut["TimeOutFlag"],configOut["DebugMsg"],configOut["EncryptionKey"]))
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
