#!/usr/bin/env python
'''
ClientMesh Rat Config Decoder
'''


__description__ = 'ClientMesh Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/06/11'

#Standard Imports Go Here
import os
import sys
import string
import base64
from optparse import OptionParser

#Non Standard Imports


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
    try:
        # Split to get start of Config
        coded_config = first_split(data)

        raw_config = conf_extract(coded_config)
        # lets Process this and format the config
        final_config = process_config(raw_config)
        return final_config
    except:
        return None
        
#Helper Functions Go Here

def stringPrintable(line):
    return filter(lambda x: x in string.printable, line)

def first_split(data):
    splits = data.split('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7e')
    if len(splits) == 2:
        return splits[1]


def base64_deocde(b64_string):
    return base64.b64decode(b64_string)

    
def conf_extract(coded_config):
    conf_list = []
    decoded_conf = base64_deocde(coded_config)
    split_list = decoded_conf.split('``')
    for conf in split_list:
        conf_list.append(conf)
    return conf_list


def process_config(raw_config):
    conf_dict = {}
    conf_dict["Domain"] = raw_config[0]
    conf_dict["Port"] = raw_config[1]
    conf_dict["Password"] = raw_config[2]
    conf_dict["CampaignID"] = raw_config[3]
    conf_dict["MsgBoxFlag"] = raw_config[4]
    conf_dict["MsgBoxTitle"] = raw_config[5]
    conf_dict["MsgBoxText"] = raw_config[6]
    conf_dict["Startup"] = raw_config[7]
    conf_dict["RegistryKey"] = raw_config[8]
    conf_dict["RegistryPersistance"] = raw_config[9]
    conf_dict["LocalKeyLogger"] = raw_config[10]
    conf_dict["VisibleFlag"] = raw_config[11]
    conf_dict["Unknown"] = raw_config[12]
    return conf_dict
    
#Recursive Function Goes Here

def runRecursive(folder, output):
    counter1 = 0
    counter2 = 0
    print "[+] Writing Configs to File {0}".format(output)
    with open(output, 'a+') as out:
        #This line will need changing per Decoder
        out.write("FileName, Domain, Port, Password, CampaignID, MsgBoxFlag, MsgBoxTitle, MsgBoxText, Startup, RegistryKey, RegistryPersistance, LocalKeyLogger, VisibleFlag, Unknown\n")    
        for server in os.listdir(folder):
            fileData = open(os.path.join(folder,server), 'rb').read()
            configOut = run(fileData)
            if configOut != None:
                #This line will need changing per Decoder
                out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12}\n'.format(server,configOut["Domain"],configOut["Port"],configOut["Password"],configOut["CampaignID"],configOut["MsgBoxFlag"],configOut["MsgBoxTitle"],configOut["MsgBoxText"],configOut["Startup"],configOut["RegistryKey"],configOut["RegistryPersistance"],configOut["LocalKeyLogger"],configOut["VisibleFlag"],configOut["Unknown"],))
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
