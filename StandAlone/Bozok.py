#!/usr/bin/env python
'''
Bozok Rat Config Decoder
'''


__description__ = 'Bozok Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.2'
__date__ = '2014/04/10'

#Standard Imports Go Here
import os
import sys
import string
from optparse import OptionParser

#Non Standard Imports
import pefile


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
	conf = {}
	rawConfig = configExtract(data).replace('\x00', '')
	config = rawConfig.split("|")
	print config
	if config != None:
		conf["ServerID"] = config[0]
		conf["Mutex"] = config[1]
		conf["InstallName"] = config[2]
		conf["StartupName"] = config[3]
		conf["Extension"] = config[4]
		conf["Password"] = config[5]
		conf["Install Flag"] = config[6]
		conf["Startup Flag"] = config[7]
		conf["Visible Flag"] = config[8]
		conf["Unknown Flag1"] = config[9]
		conf["Unknown Flag2"] = config[10]
		conf["Port"] = config[11]
		conf["Domain"] = config[12]
		conf["Unknown Flag3"] = config[13]
	print conf
	return conf
	
		
#Helper Functions Go Here

def configExtract(rawData):

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
				return data


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
