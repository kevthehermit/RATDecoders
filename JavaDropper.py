#!/usr/bin/env python
'''
Java Payload Extractor Decoder
'''
__description__ = 'Java Payload Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2015/03/03'

#Standard Imports Go Here
import os
import re
import sys
import string
import hashlib
from optparse import OptionParser
from zipfile import ZipFile
from cStringIO import StringIO
from base64 import b64decode

#Non Standard Imports
from Crypto.Cipher import ARC4, AES


#Helper Functions Go Here

def string_print(line):
    return filter(lambda x: x in string.printable, line)

#### Ciphers ####    
def decrypt_RC4(enckey, data):
    cipher = ARC4.new(enckey)
    return cipher.decrypt(data)
    
def decrypt_AES(enckey, data):
    cipher = AES.new(enckey)
    return cipher.decrypt(data)

def parse_ek(key, drop):
    enc_key = key[:16]
    coded = drop
    drop_details = key[16:]
    decoded = decrypt_AES(enc_key, coded)
    for section in drop_details.split(','):
        print b64decode(section).decode('hex')
    return decoded

def parse_load(key, drop):
    raw_key = '{0}ALSKEOPQLFKJDUSIKSJAUIE'.format(key)
    enc_key = hashlib.sha256(raw_key).hexdigest()
    decoded = decrypt_RC4(enc_key, drop)
    return decoded

def parse_stub(drop):
    keys = ['0kwi38djuie8oq89', '0B4wCrd5N2OxG93h']
    
    for key in keys:
        decoded = decrypt_AES(key, drop)
        if 'META-INF' in decoded:
            print "Found Embedded Jar"
            return decoded
        if 'Program' in decoded:
            print "Found Embedded EXE"
            return decoded

# Jar Parser
def run(file_name, save_name):
    ek = 0
    load_stub = 0
    stub_drop = False
    decoded = False
    with ZipFile(file_name, 'r') as drop_jar:
        for name in drop_jar.namelist():
            if name == 'e':
                ek += 1
            if name == 'k':
                ek += 1
            if name == 'config.ini':
                load_stub += 1
            if name == 'password.ini':
                load_stub += 1
            if name == 'stub/stub.dll':
                stub_drop = True
            
        
        if ek == 2:
            print "Found EK Dropper"
            key = drop_jar.read('k')
            drop = drop_jar.read('e')
            decoded = parse_ek(key, drop)
        
        if load_stub == 2:
            print "Found LoadStub Dropper"
            key = drop_jar.read('password.ini')
            drop = drop_jar.read('config.ini')
            decoded = parse_load(key, drop)
            
        if stub_drop:
            print "Found Stub Dropper"
            drop = drop_jar.read('stub/stub.dll')
            decoded = parse_stub(drop)
            
    if decoded:
        with open(save_name, 'wb') as out:
            out.write(decoded)
            print "Saved Decoded file to {0}".format(save_name)
    else:
        print "Unable to decode"
    return

# Main
if __name__ == "__main__":
    parser = OptionParser(usage='usage: %prog inFile outFile\n' + __description__, version='%prog ' + __version__)
    (options, args) = parser.parse_args()
    # If we dont have args quit with help page
    if len(args) > 0:
        pass
    else:
        parser.print_help()
        sys.exit()
    #Run the config extraction
    print "[+] Searching for Config"
    extracted = run(args[0], args[1])
