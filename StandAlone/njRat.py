#!/usr/bin/env python
'''
njRat Config Decoder
'''


__description__ = 'njRat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.2'
__date__ = '2015/06/13'

#Standard Imports Go Here
import os
import sys
import base64
import string
from optparse import OptionParser

#Non Standard Imports
try:
    import pype32
except ImportError:
    print "[+] Couldn't Import pype32 'https://github.com/crackinglandia/pype32'"


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python config_dict of values
'''

def run(data):
    try:
        pe = pype32.PE(data=data) 
        string_list = get_strings(pe, 2)
        #print string_list
        #parse the string list
        config_dict = parse_config(string_list)
        return config_dict
    except Exception as e:
        print e
        return None
    
        
#Helper Functions Go Here

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
            
#Turn the strings in to a python config_dict
def parse_config(string_list):
    config_dict = {}
    if string_list[5] == '0.3.5':
        config_dict["Campaign ID"] = base64.b64decode(string_list[4])
        config_dict["version"] = string_list[5]
        config_dict["Install Name"] = string_list[1]
        config_dict["Install Dir"] = string_list[2]
        config_dict["Registry Value"] = string_list[3]
        config_dict["Domain"] = string_list[7]
        config_dict["Port"] = string_list[8]
        config_dict["Network Separator"] = string_list[9]
        config_dict["Install Flag"] = string_list[6]
        
    elif string_list[6] == '0.3.6':
        config_dict["Campaign ID"] = base64.b64decode(string_list[5])
        config_dict["version"] = string_list[6]
        config_dict["Install Name"] = string_list[2]
        config_dict["Install Dir"] = string_list[3]
        config_dict["Registry Value"] = string_list[4]
        config_dict["Domain"] = string_list[8]
        config_dict["Port"] = string_list[9]
        config_dict["Network Separator"] = string_list[10]
        config_dict["Install Flag"] = string_list[11]
        
    elif  string_list[3] == '0.4.1a':
        config_dict["Campaign ID"] = base64.b64decode(string_list[2])
        config_dict["version"] = string_list[3]
        config_dict["Install Name"] = string_list[5]
        config_dict["Install Dir"] = string_list[6]
        config_dict["Registry Value"] = string_list[7]
        config_dict["Domain"] = string_list[8]
        config_dict["Port"] = string_list[9]
        config_dict["Network Separator"] = string_list[10]
        config_dict["Install Flag"] = string_list[11]

        
    elif  string_list[2] == '0.5.0E':
        config_dict["Campaign ID"] = base64.b64decode(string_list[1])
        config_dict["version"] = string_list[2]
        config_dict["Install Name"] = string_list[4]
        config_dict["Install Dir"] = string_list[5]
        config_dict["Registry Value"] = string_list[6]
        config_dict["Domain"] = string_list[7]
        config_dict["Port"] = string_list[8]
        config_dict["Network Separator"] = string_list[10]
        config_dict["Install Flag"] = string_list[9]

        
    elif  string_list[2] == '0.6.4':
        config_dict["Campaign ID"] = base64.b64decode(string_list[1])
        config_dict["version"] = string_list[2]
        config_dict["Install Name"] = string_list[3]
        config_dict["Install Dir"] = string_list[4]
        config_dict["Registry Value"] = string_list[5]
        config_dict["Domain"] = string_list[6]
        config_dict["Port"] = string_list[7]
        config_dict["Network Separator"] = string_list[8]
        config_dict["Install Flag"] = string_list[9]
        
    elif string_list[2] == '0.7.1':
        config_dict["Campaign ID"] = base64.b64decode(string_list[1])
        config_dict["version"] = string_list[2]
        config_dict["Mutex"] = string_list[3]
        config_dict["Install Name"] = string_list[4]
        config_dict["Install Dir"] = string_list[5]
        config_dict["Registry Value"] = string_list[6]
        config_dict["Domain"] = string_list[7]
        config_dict["Port"] = string_list[8]
        config_dict["Network Separator"] = string_list[10]
        config_dict["Install Flag"] = string_list[9]
        config_dict["Author"] = string_list[12]
        
    elif string_list[2] == '0.7d':
        config_dict["Campaign ID"] = base64.b64decode(string_list[1])
        config_dict["version"] = string_list[2]
        config_dict["Install Name"] = string_list[3]
        config_dict["Install Dir"] = string_list[4]
        config_dict["Registry Value"] = string_list[5]
        config_dict["Domain"] = string_list[6]
        config_dict["Port"] = string_list[7]
        config_dict["Network Separator"] = string_list[8]
        config_dict["Install Flag"] = string_list[9]
    else:
        return None
    return config_dict


#Recursive Function Goes Here

def run_recursive(folder, output):
    counter1 = 0
    counter2 = 0
    print "[+] Writing Configs to File {0}".format(output)
    with open(output, 'a+') as out:
        #This line will need changing per Decoder
        out.write("Filename,Campaign ID, Version, Install Name, Install Dir, Registry Value, Domain, Network Seperator, Install Flag\n")    
        for server in os.listdir(folder):
            file_data = open(os.path.join(folder,server), 'rb').read()
            config_dict = run(file_data)
            if config_dict != None:
                #This line will need changing per Decoder
                out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},\n'.format(server, config_dict["Campaign ID"],config_dict["version"],config_dict["Install Name"],config_dict["Install Dir"],config_dict["Registry Value"],config_dict["Domain"],config_dict["Port"],config_dict["Network Separator"],config_dict["Install Flag"]))
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
            run_recursive(args[0], args[1])
            sys.exit()
        else:
            print "[+] You need to specify Both Dir to read AND Output File"
            parser.print_help()
            sys.exit()
    
    # If not recurisve try to open file
    try:
        print "[+] Reading file"
        file_data = open(args[0], 'rb').read()
    except:
        print "[+] Couldn't Open File {0}".format(args[0])
    #Run the config extraction
    print "[+] Searching for Config"
    config = run(file_data)
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
