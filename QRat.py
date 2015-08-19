#!/usr/bin/env python
'''
QSpy Config Decoder
'''
__description__ = 'QSpy Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2015/08/19'

#Standard Imports Go Here
import os
import sys
from optparse import OptionParser
from zipfile import ZipFile
from struct import unpack

#Non Standard Imports
try:
    import javarandom
    JAVARAND = True
except:
    JAVARAND = False
    
    
def run(file_name, out_file):
    enckey = coded_jar = False
    with ZipFile(file_name, 'r') as zip:
        for name in zip.namelist():
            if name == 'e-data':
                coded_data = zip.read(name)
                seed = coded_data[:8]
                enckey = unpack('>Q', seed)[0]
                print "  [-] Testing Key {0}".format(enckey)
        
    if enckey and coded_data:
        java_rand = javarandom.Random(enckey)
        coded_data = coded_data[8:]
        print "  [-] Writing output to {0}".format(out_file)
        with open(out_file, 'wb') as out:
            for i in range(len(coded_data)):
                key = java_rand.nextInt(255)
                dec_byte = chr((ord(coded_data[i]) - key + 256) % 256)
                out.write(dec_byte)
        print "[+] File Written"
    else:
        return

# Main
if __name__ == "__main__":
    parser = OptionParser(usage='usage: %prog inFile outFile\n' + __description__, version='%prog ' + __version__)
    (options, args) = parser.parse_args()
    # Java Random
    if not JAVARAND:
        print "[!] Java Random is required 'sudo pip install java-random'"
        parser.print_help()
        sys.exit()
        
    # If we dont have args quit with help page
    if len(args) > 0:
        pass
    else:
        parser.print_help()
        sys.exit()
    #Run the config extraction
    print "[+] Processing File"
    #if you gave me two args im going to assume the 2nd arg is where you want to save the file
    if len(args) == 2:
        run(args[0], args[1])
    else:
        print "[+] You need to specify input and output files"
