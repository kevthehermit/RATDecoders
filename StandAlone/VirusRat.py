#!/usr/bin/env python
'''
VirusRat Config Decoder
'''

__description__ = 'VirusRat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net'
__version__ = '0.1'
__date__ = '2014/03/15'

import sys
import string
from optparse import OptionParser

	

def run(data):
	dict = {}
	config = data.split("abccba")
	if len(config) > 5:
		dict["Domain"] = config[1]
		dict["Port"] = config[2]
		dict["Campaign Name"] = config[3]
		dict["Copy StartUp"] = config[4]
		dict["StartUp Name"] = config[5]
		dict["Add To Registry"] = config[6]
		dict["Registry Key"] = config[7]
		dict["Melt + Inject SVCHost"] = config[8]
		dict["Anti Kill Process"] = config[9]
		dict["USB Spread"] = config[10]
		dict["Kill AVG 2012-2013"] = config[11]
		dict["Kill Process Hacker"] = config[12]
		dict["Kill Process Explorer"] = config[13]
		dict["Kill NO-IP"] = config[14]
		dict["Block Virus Total"] = config[15]
		dict["Block Virus Scan"] = config[16]
		dict["HideProcess"] = config[17]
		return dict
	else:
		return None

	
if __name__ == "__main__":
	parser = OptionParser(usage='usage: %prog inFile outConfig\n' + __description__, version='%prog ' + __version__)
	(options, args) = parser.parse_args()
	if len(args) > 0:
		pass
	else:
		parser.print_help()
		sys.exit()
	try:
		print "[+] Reading file"
		fileData = open(args[0], 'rb').read()
	except:
		print "[+] Couldn't Open File {0}".format(args[0])
	print "[+] Searching for Config"
	config = run(fileData)
	if config == None:
		print "[+] Config not found"
		sys.exit()
	if len(args) == 2:
		print "[+] Writing Config to file {0}".format(args[1])
		with open(args[1], 'a') as outFile:
			for key, value in sorted(config.iteritems()):
				clean_value = filter(lambda x: x in string.printable, value)
				outFile.write("Key: {0}\t Value: {1}\n".format(key,clean_value))
		
	else:
		print "[+] Printing Config to screen"
		for key, value in sorted(config.iteritems()):
			clean_value = filter(lambda x: x in string.printable, value)
			print "   [-] Key: {0}\t Value: {1}".format(key,clean_value)
		print "[+] End of Config"