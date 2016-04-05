#!/usr/bin/env python
'''
Adzok Rat Rat Config Extractor
'''
__description__ = 'Adzok Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.2'
__date__ = '2015/11/08'

#Standard Imports Go Here
import os
import re
import sys
import string
from optparse import OptionParser
from zipfile import ZipFile

def run(file_name):
    raw_config = False
    with ZipFile(file_name, 'r') as zip:
        for name in zip.namelist():
            if name == 'config.xml':
                raw_config = zip.read(name)
    if raw_config:
        return parse_config(raw_config)
    else:
        return
        
#Helper Functions Go Here
def string_print(line):
    return filter(lambda x: x in string.printable, line)
    
def parse_config(raw_config):
    config_dict = {}
    for line in raw_config.split('\n'):
        if line.startswith('<comment'):
            config_dict['Version'] = re.findall('>(.*?)</comment>', line)[0]
        if line.startswith('<entry key'):
            try:
                config_dict[re.findall('key="(.*?)"', line)[0]] = re.findall('>(.*?)</entry', line)[0]
            except:
                config_dict[re.findall('key="(.*?)"', line)[0]] = 'Not Set'
            finally:
                pass

    # Tidy the config
    clean_config = {}
    for k, v in config_dict.iteritems():
        if k == 'dir':
            clean_config['Install Path'] = v
        if k == 'reg':
            clean_config['Registrey Key'] = v
        if k == 'pass':
            clean_config['Password'] = v
        if k == 'hidden':
            clean_config['Hidden'] = v
        if k == 'puerto':
            clean_config['Port'] = v
        if k == 'ip':
            clean_config['Domain'] = v
        if k == 'inicio':
            clean_config['Install'] = v

    return clean_config

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
    #Run the config extraction
    print "[+] Searching for Config"
    config = run(args[0])
    #If we have a config figure out where to dump it out.
    if not config:
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
