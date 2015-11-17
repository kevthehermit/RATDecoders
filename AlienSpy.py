#!/usr/bin/env python
'''
AlienSpy Rat Rat Config Decoder
'''
__description__ = 'AlienSpy Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.4'
__date__ = '2015/10/30'

#Standard Imports Go Here
import os
import re
import sys
import json
import string
import struct
from optparse import OptionParser
from zipfile import ZipFile
from cStringIO import StringIO

#Non Standard Imports
from Crypto.Cipher import ARC4

def version_a(enckey, coded_jar):
    config_dict = {}
    for key in enckey:
        print "  [!] testing Key {0}".format(key)
        decoded_data = decrypt_RC4(key, coded_jar)
        try:
            decoded_jar = ZipFile(StringIO(decoded_data))
            raw_config = decoded_jar.read('org/jsocket/resources/config.json')
            config = json.loads(raw_config)
            for k, v in config.iteritems():
                config_dict[k] = v
            return config_dict
        except:
            pass


def version_b(enckey, coded_jar):
    config_dict = {}
    for key in enckey:
        print "  [!] testing Key {0}".format(key)
        decoded_data = decrypt_RC4(key, coded_jar)
        try:
            decoded_jar = ZipFile(StringIO(decoded_data))
            raw_config = decoded_jar.read('config.xml')

            for line in raw_config.split('\n'):
                if line.startswith('<entry key'):
                    config_dict[re.findall('key="(.*?)"', line)[0]] = re.findall('>(.*?)</entry', line)[0]
            return config_dict
        except:
            pass


def version_c(enckey, coded_jar):
    config_dict = {}
    for key in enckey:
        print "  [!] testing Key {0}".format(key)
        decoded_data = decrypt_RC6(key, coded_jar)
        try:
            decoded_jar = ZipFile(StringIO(decoded_data))
            raw_config = decoded_jar.read('org/jsocket/resources/config.json')
            config = json.loads(raw_config)
            for k, v in config.iteritems():
                config_dict[k] = v
            return config_dict
        except:
            pass


def string_print(line):
    try:
        return filter(lambda x: x in string.printable, str(line))
    except:
        return line


def decrypt_RC4(enckey, data):
	cipher = ARC4.new(enckey) # set the ciper
	return cipher.decrypt(data) # decrpyt the data


def decrypt_RC6(key, encrypted):
    def rol(a, i):
        a &= 0xFFFFFFFF
        i &= 0x1F
        x = (((a << i) & 0xFFFFFFFF) | (a >> (32 - i))) & 0xFFFFFFFF
        return x

    def ror(a, i):
        i &= 0x1F
        a &= 0xFFFFFFFF
        return ( ((a >> i) & 0xFFFFFFFF) | (a << ( (32 - i)))) & 0xFFFFFFFF


    def to_int(bytes):
        l = []
        for i in range(len(bytes)/4):
            l.append(struct.unpack("<I", bytes[i*4:(i*4)+4])[0])
        return l

    def decrypt_block(block, S):
        # Decrypt block
        ints = to_int(block)
        ints[0] = (ints[0] - S[42])
        ints[2] = (ints[2] - S[43])
        for i in reversed(range(20)):
            r = i+1

            # rotate ints
            ints = ints[-1:] + ints[:-1]

            tmp1 = rol(ints[3] * (2 * ints[3] + 1), 5)
            tmp2 = rol(ints[1] * (2 * ints[1] + 1), 5)
            ints[2] = ror(ints[2] - S[2 * r + 1], tmp2) ^ tmp1
            ints[0] = ror(ints[0] - S[2 * r], tmp1) ^ tmp2

        ints[3] = ints[3] - S[1]
        ints[1] = ints[1] - S[0]

        # convert to bytes
        decrypted = []
        for i in range(4):
            for j in range(4):
                decrypted.append(ints[i] >> (j * 8) & 0xFF)
        return decrypted

    P = 0xB7E15163
    rounds = 20
    Q = 0x9E3779B9

    # Expand key
    L = to_int(key)
    S = []
    S = [0 for i in range(44)]
    S[0] = P

    for x in range(43):
        S[x+1] = (S[x] + Q) & 0xFFFFFFFF
    i = 0
    j = 0
    A = 0
    B = 0

    for x in xrange(132):
        A = S[i] = rol((S[i] + A + B), 3)
        B = L[j] = rol((L[j] + A + B), (A + B))
        i = (i + 1) % 44
        j = (j + 1) % 8

    # Decrypt blocks
    decrypted = []
    while True:
        decrypted += decrypt_block(encrypted[:16], S)
        encrypted = encrypted[16:]
        if not encrypted:
            break
    data = bytearray(decrypted)
    data = data.rstrip(b"\x00")
    return data

def run(file_name):
    config_dict = False
    jar = ZipFile(file_name, 'r')
    # Version A
    if 'a.txt' and 'b.txt' in jar.namelist():
        pre_key = jar.read('a.txt')
        enckey = ['{0}{1}{0}{1}a'.format('plowkmsssssPosq34r', pre_key),
                  '{0}{1}{0}{1}a'.format('kevthehermitisaGAYXD', pre_key)
                  ]
        coded_jar = jar.read('b.txt')
        config_dict = version_a(enckey, coded_jar)

    # Version B
    if 'ID' and 'MANIFEST.MF' in jar.namelist():
        pre_key = jar.read('ID')
        enckey = ['{0}H3SUW7E82IKQK2J2J2IISIS'.format(pre_key)]
        coded_jar = jar.read('MANIFEST.MF')
        config_dict = version_b(enckey, coded_jar)

    # Version C
    if 'resource/password.txt' and 'resource/server.dll' in jar.namelist():
        pre_key = jar.read('resource/password.txt')
        enckey = ['CJDKSIWKSJDKEIUSYEIDWE{0}'.format(pre_key)]
        coded_jar = jar.read('resource/server.dll')
        config_dict = version_c(enckey, coded_jar)

    # Version D
    if 'java/stubcito.opp' and 'java/textito.isn' in jar.namelist():
        pre_key = jar.read('java/textito.isn')
        enckey = ['TVDKSIWKSJDKEIUSYEIDWE{0}'.format(pre_key)]
        coded_jar = jar.read('java/stubcito.opp')
        config_dict = version_c(enckey, coded_jar)
        
    # Version E
    if 'java/textito.text' and 'java/resource.xsx' in jar.namelist():
        pre_key = jar.read('java/textito.text')
        enckey = ['kevthehermitGAYGAYXDXD{0}'.format(pre_key)]
        coded_jar = jar.read('java/resource.xsx')
        config_dict = version_c(enckey, coded_jar)

    return config_dict


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
                outFile.write("Key: {0}\t Value: {1}\n".format(key,string_print(value)))
    # if no seconds arg then assume you want it printing to screen
    else:
        print "[+] Printing Config to screen"
        for key, value in sorted(config.iteritems()):
            clean_value = string_print(value)
            print "   [-] Key: {0}\t Value: {1}".format(key,clean_value)
        print "[+] End of Config"
