#!/usr/bin/env python
'''
Pandora Config Decoder
'''

__description__ = 'Pandora Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net'
__version__ = '0.1'
__date__ = '2014/03/15'

import sys
import string
from optparse import OptionParser
try:
	import pefile
except ImportError:
	print "[+] Couldnt Import pefile. Try 'sudo pip install pefile'"
	

def configExtract(rawData):
	try:
		pe = pefile.PE(data=rawData)

		try:
		  rt_string_idx = [
		  entry.id for entry in 
		  pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
		except ValueError, e:
			sys.exit()
		except AttributeError, e:
			sys.exit()

		rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

		for entry in rt_string_directory.directory.entries:
			if str(entry.name) == "CFG":
				data_rva = entry.directory.entries[0].data.struct.OffsetToData
				size = entry.directory.entries[0].data.struct.Size
				data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
				cleaned = data.replace('\x00', '')
				config = cleaned.split('##')
				return config
	except:
		print "Couldn't Locate the Config, Is it Packed?"
		return None			

def run(data):
	dict = {}
	config = data.split("abccba")
	if len(config) > 5:
		dict["Domain"] = config[1]#
		dict["Port"] = config[2]#
		dict["Campaign Name"] = config[3]#
		dict["Copy StartUp"] = config[4]#
		dict["Unknown"] = config[5]#
		dict["Add To Registry"] = config[6]#
		dict["Registry Key"] = config[7]#
		dict["Password"] = config[8]#
		dict["Anti Kill Process"] = config[9]#
		dict["USB Spread"] = config[10]#
		dict["Anti VMWare VirtualBox"] = config[11]
		dict["Kill Sandboxie"] = config[12]#
		dict["Kill WireShark / Apate DNS"] = config[13]#
		dict["Kill NO-IP"] = config[14]#
		dict["Block Virus Total"] = config[15]#
		dict["Install Name"] = config[16]#
		dict["ByPass Malware Bytes"] = config[20]#
		dict["Kill SpyTheSPy"] = config[21]#
		dict["Connection Delay"] = config[22]#
		dict["Copy To All Drives"] = config[23]#
		dict["HideProcess"] = config[24]
		if config[17] == "True":
			dict["Install Path"] = "App Data"
		if config[18] == "True":
			dict["Install Path"] = "TEMP"
		if config[19] == "True":
			dict["Install Path"] = "Documents"
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
				outFile.write("Key: {0}\t\t Value: {1}\n".format(key,clean_value))
		
	else:
		print "[+] Printing Config to screen"
		for key, value in sorted(config.iteritems()):
			clean_value = filter(lambda x: x in string.printable, value)
			print "   [-] Key: {0}\t\t Value: {1}".format(key,clean_value)
		print "[+] End of Config"