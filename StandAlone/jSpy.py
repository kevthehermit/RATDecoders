#!/usr/bin/env python
'''
jSpy Config Decoder
'''
__description__ = 'jSpy Rat Config Extractor'
__author__ = 'Anthony Kasza'
__version__ = '0.1'
__date__ = '2016/03/15'

import sys
from optparse import OptionParser
from zipfile import ZipFile



def run(file_name, out_file):
  fields = ['IP/DNS', 'Port', 'Startup', 'Identification', 'Version', 'Stealth Mode']
  with ZipFile(file_name, 'r') as zf:
    for name in zf.namelist():
      if 'config.txt' in name:
        # config.txt should be a file with a single line of colon seperated values
        config_line = zf.read(name)
        try:
          config = dict(zip(fields, config_line.split(':')))
        except:
          print "  [-] Possible configuration file found, but cannot parse: {0}".format(name)

  if config:
    if out_file:
      with open(out_file, 'wb') as f:
        print "  [-] Writing output to {0}".format(out_file)
        for k,v in config.iteritems():
          f.write("  [-] Key: {0}\tValue: {1}\n".format(k, v))
        print "[+] File Written"
    else:
      print "[+] Printing Config to screen"
      for k,v in config.iteritems():
        print "  [-] Key: {0}\tValue: {1}".format(k, v)

  else:
    print "  [-] Unable to locate any possible configuration files"



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
