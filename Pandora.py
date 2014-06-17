#!/usr/bin/env python
'''
Pandora Rat Config Decoder
'''


__description__ = 'Pandora Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.2'
__date__ = '2014/06/17'

#Standard Imports Go Here
import os
import sys
import base64
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
    
    config = configExtract(data)
    if len(config) == 19:
        return version_21(config)
    if len(config) == 20:
        return version_22(config)


    

def version_21(config):
    if config != None:
        for x in config:
            print x
        newConfig = {}
        newConfig["Version"] = "2.1"
        newConfig["Domain"] = config[0]
        newConfig["Port"] = config[1]
        newConfig["Password"] = config[2]
        newConfig["Install Path"] = config[3]
        newConfig["Install Name"] = config[4]
        newConfig["HKCU Key"] = config[5]
        newConfig["ActiveX Key"] = config[6]
        newConfig["Install Flag"] = config[7]
        newConfig["StartupFlag"] = config[8] # pers
        newConfig["ActiveXFlag"] = config[9] # use active x
        newConfig["HKCU Flag"] = config[10] # pers
        newConfig["Mutex"] = config[11] #
        newConfig["userMode Hooking"] = config[12] # usermode unhooking
        newConfig["Melt"] = config[13] # melt
        newConfig["Melt"] = config[13] # melt
        newConfig["Keylogger"] = config[14] # Keylogger
        newConfig["Campaign ID"] = config[15]
        newConfig["UnknownFlag9"] = config[16]
        return newConfig
    else:
        return None

def version_22(config):
    if config != None:
        for x in config:
            print x
        newConfig = {}
        newConfig["Version"] = "2.2"
        newConfig["Domain"] = config[0]
        newConfig["Port"] = config[1]
        newConfig["Password"] = config[2]
        newConfig["Install Path"] = config[3]
        newConfig["Install Name"] = config[4]
        newConfig["HKCU Key"] = config[5]
        newConfig["ActiveX Key"] = config[6]
        newConfig["Install Flag"] = config[7]
        newConfig["StartupFlag"] = config[8] # pers
        newConfig["ActiveXFlag"] = config[9] # use active x
        newConfig["HKCU Flag"] = config[10] # pers
        newConfig["Mutex"] = config[11] #
        newConfig["userMode Hooking"] = config[12] # usermode unhooking
        newConfig["Melt"] = config[13] # melt
        newConfig["Melt"] = config[13] # melt
        newConfig["Keylogger"] = config[14] # Keylogger
        newConfig["Campaign ID"] = config[15]
        newConfig["UnknownFlag9"] = config[16]
        return newConfig
    else:
        return None


#Helper Functions Go Here
def configExtract(rawData):
    try:
        pe = pefile.PE(data=rawData)
        try:
          rt_string_idx = [
          entry.id for entry in 
          pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
        except ValueError, e:
            sys.exit()
        except AttributeError, e:
            sys.exit()
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "CFG":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                cleaned = data.replace('\x00', '')
                config = cleaned.split('##')
                return config
    except:
        print "Couldn't Locate the Config, Is it Packed?"
        return None    


#Recursive Function Goes Here

def runRecursive(folder, output):
    counter1 = 0
    counter2 = 0
    print "[+] Writing Configs to File {0}".format(output)
    with open(output, 'a+') as out:
        #This line will need changing per Decoder
        out.write("Filename,Domain, Port, Password, Install Path, Install Name, HKCU Startup, ActiveX Startup, ID,Campaign ID\n")    
        for server in os.listdir(folder):
            fileData = open(os.path.join(folder,server), 'rb').read()
            configOut = run(fileData)
            if configOut != None:
                #This line will need changing per Decoder
                out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},\n'.format(server, configOut["Domain"],configOut["Port"],configOut["Password"],configOut["Install Path"],configOut["Install Name"],configOut["HKCU Startup"],configOut["ActiveX Install"],configOut["ID"],configOut["Campaign ID"]))
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
