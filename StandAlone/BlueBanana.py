#!/usr/bin/env python
'''
BlueBanana Rat Config Decoder
'''


__description__ = 'BlueBanana Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/04/10'

#Standard Imports Go Here
import os
import sys
import string
from zipfile import ZipFile
from cStringIO import StringIO
from optparse import OptionParser

#Non Standard Imports
try:
	from Crypto.Cipher import AES
except ImportError:
	print "[+] Couldn't Import Cipher, try 'sudo pip install pycrypto'"


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
	newZip = StringIO(data)
	with ZipFile(newZip) as zip:
		for name in zip.namelist(): # get all the file names
			if name == "config.txt": # this file contains the encrypted config
				conFile = zip.read(name)
	if conFile: # 
		confRaw = decryptConf(conFile)
		conf = configParse(confRaw)
	return conf
	
		
#Helper Functions Go Here

def DecryptAES(enckey, data):
	cipher = AES.new(enckey) # set the cipher
	return cipher.decrypt(data) # decrpyt the data

def decryptConf(conFile):
	key1 = "15af8sd4s1c5s511"
	key2 = "4e3f5a4c592b243f"
	first = DecryptAES(key1, conFile.decode('hex'))
	second = DecryptAES(key2, first[:-16].decode('hex'))
	return second
	
def configParse(confRaw):
	config = {}
	clean = filter(lambda x: x in string.printable, confRaw)
	list = clean.split("<separator>")
	config["Domain"] = list[0]
	config["Password"] = list[1]
	config["Port1"] = list[2]
	config["Port2"] = list[3]
	if len(list) > 4:
		config["InstallName"] = list[4]
		config["JarName"] = list[5]
	return config

#Recursive Function Goes Here


# Main

if __name__ == "__main__":
	parser = OptionParser(usage='usage: %prog inFile outConfig\n' + __description__, version='%prog ' + __version__)
	parser.add_option("-r", "--recursive", action='store_true', default=False, help="Recursive Mode")
	(options, args) = parser.parse_args()
	# If we dont have args quit with help page
	if len(args) > 0:
		pass
	else:
		parser.print_help()
		sys.exit()
	# if we want a recursive extract run this function
	if options.recursive == True:
		print "[+] Sorry Not Here Yet Come Back Soon"
	
	# If not recurisve try to open file
	try:
		print "[+] Reading file"
		fileData = open(args[0], 'rb').read()
	except:
		print "[+] Couldn't Open File {0}".format(args[0])
	#Run the config extraction
	print "[+] Searching for Config"
	config = run(fileData)
	#If we have a config figure out where to dump it out.
	if config == None:
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
