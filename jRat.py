#!/usr/bin/env python
'''
jRat Config Parser

'''
__description__ = 'jRat Config Parser'
__author__ = 'Kevin Breen'
__version__ = '0.1'
__date__ = '2013/08/05'

import sys
import base64
import string
from zipfile import ZipFile
from optparse import OptionParser
try:
	from Crypto.Cipher import AES
	from Crypto.Cipher import DES3
except ImportError:
	print "Cannot import PyCrypto, Is it installed?"


def main():
	parser = OptionParser(usage='usage: %prog [options] InFile SavePath\n' + __description__, version='%prog ' + __version__)
	parser.add_option("-v", "--verbose", action='store_true', default=False, help="Verbose Output")
	(options, args) = parser.parse_args()
	if len(args) != 2:
		parser.print_help()
		sys.exit()

	archive = args[0]
	outfile = args[1]
	dropper = None
	conf = None
	with ZipFile(archive, 'r') as zip:
		for name in zip.namelist(): # get all the file names
			if name == "key.dat": # this file contains the encrytpion key
				enckey = zip.read(name)
			if name == "enc.dat": # if this file exists, jrat has an installer / dropper				
				dropper = zip.read(name)
			if name == "config.dat": # this is the encrypted config file
				conf = zip.read(name)
		if dropper != None: # we need to process the dropper first
			print "Dropper Detected"
			ExtractDrop(enckey, dropper, outfile)
		elif conf != None: # if theres not dropper just decrpyt the config file
			if len(enckey) == 16: # version > 3.2.3 use AES
				cleandrop = DecryptAES(enckey, conf)
				WriteReport(enckey, outfile, cleandrop)
			elif len(enckey) == 24: # versions <= 3.2.3 use DES
				cleandrop = DecryptDES(enckey, conf)
				WriteReport(enckey, outfile, cleandrop)

def ExtractDrop(enckey, data, outfile):
	split = enckey.split('\x2c')
	key = split[0][:16]
	with open(outfile, 'a') as new:
		print "### Dropper Information ###"
		new.write("### Dropper Information ###\n")
		for x in split: # grab each line of the config and decode it.		
			try:
				drop = base64.b64decode(x).decode('hex')
				print drop
				new.write(drop+'\n')
			except:
				drop = base64.b64decode(x[16:]).decode('hex')
				print drop
				new.write(drop+'\n')
	newzipdata = DecryptAES(key, data)
	from cStringIO import StringIO
	newZip = StringIO(newzipdata) # Write new zip file to memory instead of to disk
	with ZipFile(newZip) as zip:
		for name in zip.namelist():
			if name == "key.dat": # contains the encryption key
				enckey = zip.read(name)
			if name == "config.dat":
				conf = zip.read(name) # the encrypted config file
			if len(enckey) == 16: # version > 3.2.3 use AES
				printkey = enckey.encode('hex')
				print "AES Key Found: ", printkey
				cleandrop = DecryptAES(enckey, conf) # pass to the decrpyt function
				print "### Configuration File ###"
				WriteReport(printkey, outfile, cleandrop)
			elif len(enckey) == 24: # versions <= 3.2.3 use DES
				printkey = enckey
				print "DES Key Found: ", enckey
				cleandrop = DecryptDES(enckey, conf) # pass to the decrpyt function
				print "### Configuration File ###"
				WriteReport(enckey, outfile, cleandrop)
				
def DecryptAES(enckey, data):					
		cipher = AES.new(enckey) # set the cipher
		return cipher.decrypt(data) # decrpyt the data
		
def DecryptDES(enckey, data):

		cipher = DES3.new(enckey) # set the ciper
		return cipher.decrypt(data) # decrpyt the data

def WriteReport(key, outfile, data): # this should be self expanatory		
	split = data.split("SPLIT")
	with open(outfile, 'a') as new:
		new.write(key)
		new.write('\n')
		for s in split:
			stripped = (char for char in s if 32 < ord(char) < 127) # im only interested in ASCII Characters
			line = ''.join(stripped)
			#if options.verbose == True:
			print line
			new.write(line)
			new.write('\n')
	print "Config Written To: ", outfile


if __name__ == "__main__":
	main()
