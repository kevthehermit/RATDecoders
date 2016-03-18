#!/usr/bin/env python
'''
jSpy Config Decoder
'''
__description__ = 'OS Celestial Rat Config Extractor'
__author__ = 'Anthony Kasza'
__version__ = '0.1'
__date__ = '2016/03/17'

# Note: OS Celestial is *very* likely an updated version of jSpy

import re
import sys
import zlib
import base64 as b64
from optparse import OptionParser
from zipfile import ZipFile
try:
  from StringIO import cStringIO
except:
  from StringIO import StringIO


def xor(enc, key):
  dec = ''
  i = 0
  while i < len(enc):
    dec += chr(ord(enc[i]) ^ ord(key[i % len(key)]))
    i += 1
  return dec


def decode_config(zf):
  fields = ['port', 'startup', 'id', 'version', 'stealth', 'melt']
  dat = {}
  if 'com/stub/config/config.txt' in zf.namelist():
    raw = zf.read('com/stub/config/config.txt')
    raw, key = raw.strip().split(':')
    data = xor(b64.b64decode(raw), key)
    dat.update( dict(zip(fields, data.split(':'))) )
  if 'com/stub/config/hosts.txt' in zf.namelist():
    raw = zf.read('com/stub/config/hosts.txt')
    raw = raw.strip()
    data = xor(b64.b64decode(raw), key)
    data = [each for each in re.split('\r?\n', data) if each]
    dat['ip'] = data
  if 'com/stub/config/plugins.txt' in zf.namelist():
    raw = zf.read('com/stub/config/plugins.txt')
    raw = raw.strip()
    data = xor(b64.b64decode(raw), key)
    dat['plugins'] = data
  return dat



def run(file_name, out_file):
  with ZipFile(file_name, 'r') as zf:
    # file is a JAR that drops the implant JAR
    if 'config/resource.dat' in zf.namelist():
      embeded_jar = StringIO()
      embeded_jar.write(zlib.decompress(zf.read('config/resource.dat')))
      with ZipFile(embeded_jar, 'r') as new_zf:
        config = decode_config(new_zf)
    # file is the dropped JAR
    elif 'com/stub/config/config.txt' in zf.namelist():
      config = decode_config(zf)
    else:
      print "  [-] Unable to locate any possible configuration files"

  # we found a config, woot
  if len(config.keys()) > 0:
    if out_file:
      with open(out_file, 'wb') as f:
        print "  [-] Writing output to {0}".format(out_file)
        for k,v in config.iteritems():
          f.write("  [-] Key: {0}\tValue: {1}\n".format(k, v))
        print "[+] File Written"
    else:
      print "[+] Printing config to screen"
      for k,v in config.iteritems():
        print "  [-] Key: {0}\tValue: {1}".format(k, v)
      print "[+] End of config"
  else:
    print "  [-] Unable to locate any possible configuration files"
  return


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
  print "[+] Processing File"
  #if you gave me two args im going to assume the 2nd arg is where you want to save the file
  if len(args) == 2:
    run(args[0], args[1])
  elif len(args) == 1:
    run(args[0], None)
  else:
    print "[+] You need to specify input"
