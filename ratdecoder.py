#!/usr/bin/env python
import os
import sys
import importlib
import hashlib
import yara
import subprocess
import tempfile
from optparse import OptionParser

from decoders import JavaDropper

__description__ = 'RAT Config Extractor'
__author__ = 'Kevin Breen, https://techanarchy.net, https://malwareconfig.com'
__version__ = '1.0'
__date__ = '2016/04'
rule_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'yaraRules', 'yaraRules.yar')


def unpack(raw_data):
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(raw_data)
    f.close()
    try:
        subprocess.call("(upx -d %s)" %f.name, shell=True)
    except Exception as e:
        print 'UPX Error {0}'.format(e)
        return
    new_data = open(f.name, 'rb').read()
    os.unlink(f.name)
    return new_data


# Yara Scanner Returns the Rule Name
def yara_scan(raw_data):
    yara_rules = yara.compile(rule_file)
    matches = yara_rules.match(data=raw_data)
    if len(matches) > 0:
        return str(matches[0])
    else:
        return


def run(raw_data):
    # Get some hashes
    md5 = hashlib.md5(raw_data).hexdigest()
    sha256 = hashlib.sha256(raw_data).hexdigest()

    print "   [-] MD5: {0}".format(md5)
    print "   [-] SHA256: {0}".format(sha256)

    # Yara Scan
    family = yara_scan(raw_data)



    # UPX Check and unpack
    if family == 'UPX':
        print "  [!] Found UPX Packed sample, Attempting to unpack"
        raw_data = unpack(raw_data)
        family = yara_scan(raw_data)

        if family == 'UPX':
            # Failed to unpack
            print "  [!] Failed to unpack UPX"
            return

    # Java Dropper Check
    if family == 'JavaDropper':
        print "  [!] Found Java Dropped, attemping to unpack"
        raw_data = JavaDropper.run(raw_data)
        family = yara_scan(raw_data)

        if family == 'JavaDropper':
            print "  [!] Failed to unpack JavaDropper"
            return

    if not family:
        print "    [!] Unabel to match your sample to a decoder"
        return

    # Import decoder
    try:
        module = importlib.import_module('decoders.{0}'.format(family))
        print "[+] Importing Decoder: {0}".format(family)
    except ImportError:
        print '    [!] Unable to import decoder {0}'.format(family)
        return

    # Get config data
    try:
        config_data = module.config(raw_data)
    except Exception as e:
        print 'Conf Data error with {0}. Due to {1}'.format(family, e)
        return ['Error', 'Error Parsing Config']

    return config_data


def print_output(config_dict, output):
    if output:
        with open(output, 'a') as out:
            print "    [+] Printing Config to Output"
            for key, value in sorted(config_dict.iteritems()):
                out.write("       [-] Key: {0}\t Value: {1}".format(key,value))
            out.write('*'*20)
            print "    [+] End of Config"
    else:
        print "[+] Printing Config to screen"
        for key, value in sorted(config_dict.iteritems()):
            print "   [-] Key: {0}\t Value: {1}".format(key,value)
        print "[+] End of Config"



if __name__ == "__main__":
    parser = OptionParser(usage='usage: %prog file / dir\n' + __description__, version='%prog ' + __version__)
    parser.add_option("-r", "--recursive", action='store_true', default=False, help="Recursive Mode")
    parser.add_option("-f", "--family", help="Force a specific family")
    parser.add_option("-l", "--list", action="store_true", default=False, help="List Available Decoders")
    parser.add_option("-o", "--output", help="Output Config elements to file.")
    (options, args) = parser.parse_args()

    # Print list
    if options.list:
        print "[+] Listing Available Decoders"
        for filename in os.listdir('decoders'):
            print "  [-] {0}".format(filename)
        sys.exit()

    # We need at least one arg
    if len(args) < 1:
        print "[!] Not enough Arguments, Need at least file path"
        parser.print_help()
        sys.exit()

    # Check for file or dir
    is_file = os.path.isfile(args[0])
    is_dir = os.path.isdir(args[0])

    if options.recursive:
        if not is_dir:
            print "[!] Recursive requires a directory not a file"
            sys.exit()

        # Read all the things
        for filename in os.listdir(args[0]):
            file_data = open(os.path.join(args[0], filename), 'rb').read()
            print "[+] Reading {0}".format(filename)
            config_data = run(file_data)

    else:
        if not is_file:
            print "[!] You did not provide a valid file."
            sys.exit()

        # Read in the file.
        file_data = open(args[0], 'rb').read()
        print "[+] Reading {0}".format(args[0])
        config_data = run(file_data)
        print_output(config_data, options.output)
