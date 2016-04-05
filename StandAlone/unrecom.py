#!/usr/bin/env python
'''
Unrecom Rat Config Parser

'''
__description__ = 'unrecom rat Config Parser'
__author__ = 'Kevin Breen'
__version__ = '0.1'
__date__ = '2014/05/22'

import sys

import string
from zipfile import ZipFile
from optparse import OptionParser
import xml.etree.ElementTree as ET

try:
    from Crypto.Cipher import ARC4
except ImportError:
    print "Cannot import PyCrypto, Is it installed?"


def main():
    parser = OptionParser(usage='usage: %prog jarfile\n' + __description__, version='%prog ' + __version__)
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.print_help()
        sys.exit()
    archive = args[0]
    # Decrypt & Extract the embedded Jar
    print "[+] Reading File"
    try:
        embedded = extract_embedded(archive)
    except:
        print "[+] Failed to Read File"
        sys.exit()
    # Look for our config file
    print "    [-] Looking for Config"
    config = parse_embedded(embedded)
    # Print to pretty Output
    print "[+] Found Config"
    print_config(config)    
    
def extract_embedded(archive):
    enckey = None
    adwind_flag = False
    with ZipFile(archive, 'r') as zip:
        for name in zip.namelist(): # get all the file names
            if name == "load/ID": # contains first part of key
                partial_key = zip.read(name)
                enckey = partial_key + 'DESW7OWKEJRU4P2K' # complete key
                print "    [-] Found Key {0}".format(zip.read(name))
            if name == "load/MANIFEST.MF": # this is the embedded jar                
                raw_embedded = zip.read(name)
            if name == "load/stub.adwind": # This is adwind 3
                raw_embedded = zip.read(name)
                adwind_flag = True
                
    if adwind_flag:
        enckey = partial_key
    if enckey != None:
        # Decrypt The raw file
        print "    [-] Decrypting Embedded Jar"
        dec_embedded = decrypt_arc4(enckey, raw_embedded)
        return dec_embedded
    else:
        print "[+] No embedded File Found"
        sys.exit()


def parse_embedded(data):
    newzipdata = data
    from cStringIO import StringIO
    newZip = StringIO(newzipdata) # Write new zip file to memory instead of to disk
    with ZipFile(newZip) as zip:
        for name in zip.namelist():
            if name == "config.xml": # this is the config in clear
                config = zip.read(name)
    return config
        
def decrypt_arc4(enckey, data):
        cipher = ARC4.new(enckey) # set the ciper
        return cipher.decrypt(data) # decrpyt the data

def print_config(config):
    xml = filter(lambda x: x in string.printable, config)
    root = ET.fromstring(xml)
    raw_config = {}
    for child in root:
        if child.text.startswith("Unrecom"):
            raw_config["Version"] = child.text
        else:
            raw_config[child.attrib["key"]] = child.text
    
    for key, value in sorted(raw_config.iteritems()):
        print "    [-] Key: {0}\t Value: {1}".format(key, value)
    
    
if __name__ == "__main__":
    main()
