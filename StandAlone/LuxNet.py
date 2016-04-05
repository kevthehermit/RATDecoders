#!/usr/bin/env python
'''
LuxNet Rat Config Decoder
'''


__description__ = 'Luxnet Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/06/17'

#Standard Imports Go Here
import os
import sys
import string
from struct import unpack
from optparse import OptionParser

#Non Standard Imports


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
    # Split to get start of Config
    get_config = first_split(data)
    if get_config == None:
        return None
    # If the split works try to walk the strings
    raw_config = data_walk(get_config)
    # lets Process this and format the config
    config_dict = parse_config(raw_config)
    return config_dict
    
        
#Helper Functions Go Here
def calc_length(byteStr):
    #try:
        return unpack(">H", byteStr)[0]
    #except:
        #return None

def string_print(line):
    return filter(lambda x: x in string.printable, line)

def first_split(data):
    split_strings = ['\x5B\x53\x00\x6F\x00\x66\x00\x74\x00\x77\x00\x61\x00\x72\x00\x65\x00\x5C\x00\x4D\x00\x69\x00\x63\x00\x72\x00\x6F\x00\x73\x00\x6F\x00\x66\x00\x74\x00\x5C\x00\x57\x00\x69\x00\x6E\x00\x64\x00\x6F\x00\x77\x00\x73\x00\x5C\x00\x43\x00\x75\x00\x72\x00\x72\x00\x65\x00\x6E\x00\x74\x00\x56\x00\x65\x00\x72\x00\x73\x00\x69\x00\x6F\x00\x6E\x00\x5C\x00\x52\x00\x75\x00\x6E\x00', '\x79\x55\x00\x32\x00\x39\x00\x6D\x00\x64\x00\x48\x00\x64\x00\x68\x00\x63\x00\x6D\x00\x56\x00\x63\x00\x54\x00\x57\x00\x6C\x00\x6A\x00\x63\x00\x6D\x00\x39\x00\x7A\x00\x62\x00\x32\x00\x5A\x00\x30\x00\x58\x00\x46\x00\x64\x00\x70\x00\x62\x00\x6D\x00\x52\x00\x76\x00\x64\x00\x33\x00\x4E\x00\x63\x00\x51\x00\x33\x00\x56\x00\x79\x00\x63\x00\x6D\x00\x56\x00\x75\x00\x64\x00\x46\x00\x5A\x00\x6C\x00\x63\x00\x6E\x00\x4E\x00\x70\x00\x62\x00\x32\x00\x35\x00\x63\x00\x55\x00\x6E\x00\x56\x00\x75\x00']
    for split_string in split_strings:
        splits = data.split(split_string)
        if len(splits) == 2:
            return splits[1]

    
def data_walk(splitdata):
    stringList = []
    offset = 0
    config = bytearray(splitdata)
    count = 0
    while offset < len(config) and count < 2:
        if str(config[offset]) == '1':
            len_bytes = '{0}{1}'.format(chr(0),chr(config[offset+1]))
        else:
            len_bytes = str(config[offset:offset+2])
        new_length = calc_length(len_bytes)
        that = config[offset+2:offset+int(new_length)]
        stringList.append(str(that.replace("\x00", "")))
        offset += int(new_length+1)
        count += 1
    return stringList

def parse_config(raw_config):
    conf_dict = {}
    conf_dict['Domain'] = raw_config[0]
    conf_dict['Port'] = raw_config[1]
    return conf_dict
    
#Recursive Function Goes Here

def runRecursive(folder, output):
    counter1 = 0
    counter2 = 0
    print "[+] Writing Configs to File {0}".format(output)
    with open(output, 'a+') as out:
        #This line will need changing per Decoder
        out.write("Filename,Domain, Port\n")    
        for server in os.listdir(folder):
            fileData = open(os.path.join(folder,server), 'rb').read()
            config_out = run(fileData)
            if config_out != None:
                #This line will need changing per Decoder
                out.write('{0},{1},{2}\n'.format(server, config_out["Domain"],config_out["Port"]))
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
