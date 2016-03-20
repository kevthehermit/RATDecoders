#!/usr/bin/env python
'''
OS Celestial Config Decoder
'''
__description__ = 'OS Celestial Rat Config Extractor'
__author__ = 'Anthony Kasza'
__version__ = '0.269'
__date__ = '2016/03/20'

# Note: OS Celestial is *very* likely an updated version of jSpy

import re
import sys
import zlib
import base64 as b64
from optparse import OptionParser
from zipfile import ZipFile
try:
  from cStringIO import cStringIO
except:
  from StringIO import StringIO



def xor_with_key(enc, key):
  dec = ''
  i = 0
  while i < len(enc):
    dec += chr(ord(enc[i]) ^ ord(key[i % len(key)]))
    i += 1
  return dec


def decode(enc, key):
  return xor_with_key(b64.b64decode(enc), key)


def readIO(args):
  directory = "osc_files";
#  localPath = new File(System.getProperty("user.home"), directory);
  ip = set([])
  version = "Undefined"
  port = 3175
  id = "Undefined"
  disableKeylogger = 'false'
  visible = 'true'
  key = ''
  ip.add("127.0.0.1")
  melt = ''
  stealth = ''
  startup = ''

  for i in range(0, len(args)):
    if i == 0:
      orangeBits = args[i].split(":");
      if args[0]:
        stealth = orangeBits[0]
      if args[1]:
        startup = orangeBits[1]
      if args[2]:
        melt = orangeBits[2]
      continue
    if i == 1:
      config = args[i]
      if len(config.split(":")) == 2:
        enc_config, key = config.split(":")
        config = decode(enc_config, key);
      configsplit = config.split(":");
      port = configsplit[0]
      id = configsplit[1]
      version = configsplit[2]
      if len(configsplit) > 3:
        disableKeylogger = configsplit[3]
      else:
        disableKeylogger = 'true'
      if len(configsplit) > 4:
        visible = configsplit[4]
        continue
      visible = 'true'
      continue
    if i == 2:
      hosts = [each for each in re.split("\\r?\\n", decode(args[i], key)) if each]
      if len(hosts) > 0:
        ip = set(hosts)
      continue
  return {'directory': directory, 'ip': ip, 'version': version, 'port': port, 'id': id,
          'disableKeylogger': disableKeylogger, 'visible': visible, 'key': key,
          'melt': melt, 'stealth': stealth, 'startup': startup}



#config.txt, stubconfig.txt, hosts.txt

def decode_config(zf):
  if 'config/stubconfig.txt' in zf.namelist():
    args = []
    try:
      config = zf.read("config/config.txt")
      args.append(config)
    except:
      pass
    try:
      stubconfig = zf.read("config/stubconfig.txt")
      args.append(stubconfig)
    except:
      pass
    try:
      hosts = zf.read("config/hosts.txt")
      args.append(hosts)
    except:
      pass
    return readIO(args)
  else:
    # older versions of implants are weird
    fields = ['port', 'startup', 'id', 'version', 'stealth', 'melt']
    dat = {}
    if 'com/stub/config/config.txt' in zf.namelist():
      raw = zf.read('com/stub/config/config.txt')
      raw, key = raw.strip().split(':')
      data = decode(raw, key)
      dat.update( dict(zip(fields, data.split(':'))) )
    if 'com/stub/config/hosts.txt' in zf.namelist():
      raw = zf.read('com/stub/config/hosts.txt')
      raw = raw.strip()
      data = decode(raw, key)
      data = set([each for each in re.split('\r?\n', data) if each])
      dat['ip'] = data
    if 'com/stub/config/plugins.txt' in zf.namelist():
      raw = zf.read('com/stub/config/plugins.txt')
      raw = raw.strip()
      data = decode(raw, key)
      dat['plugins'] = data
    return dat


def run(file_name, out_file):
  with ZipFile(file_name, 'r') as zf:
    # NOTE: order matters here - some files are located in different vesions
    if 'config/stubconfig.txt' in zf.namelist():
      config = decode_config(zf)
    # file is a JAR that drops the implant JAR
    elif 'config/resource.dat' in zf.namelist():
      embeded_jar = StringIO()
      embeded_jar.write(zlib.decompress(zf.read('config/resource.dat')))
      with ZipFile(embeded_jar, 'r') as new_zf:
        config = decode_config(new_zf)
    # file is the dropped JAR
    elif 'com/stub/config/config.txt' in zf.namelist():
      config = decode_config(zf)
    else:
      print "  [-] Unable to locate any possible configuration files"
      return

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
import re
import base64 as b64
