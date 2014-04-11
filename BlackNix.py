#!/usr/bin/env python
'''
BlackNix Rat Config Decoder
'''


__description__ = 'BlackNix Rat Config Extractor'
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



# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
	conf = {}
	config = configExtract(data)
	if config != None:
		for i in range(0,len(config)):
			print i, decode(config[i])[::-1]
		conf["Mutex"] = decode(config[1])[::-1]
		conf["Anti Sandboxie"] = decode(config[2])[::-1]
		conf["Max Folder Size"] = decode(config[3])[::-1]
		conf["Delay Time"] = decode(config[4])[::-1]
		conf["Password"] = decode(config[5])[::-1]
		conf["Kernel Mode Unhooking"] = decode(config[6])[::-1]
		conf["User More Unhooking"] = decode(config[7])[::-1]
		conf["Melt Server"] = decode(config[8])[::-1]
		conf["Offline Screen Capture"] = decode(config[9])[::-1]
		conf["Offline Keylogger"] = decode(config[10])[::-1]
		conf["Copy To ADS"] = decode(config[11])[::-1]
		conf["Domain"] = decode(config[12])[::-1]
		conf["Persistence Thread"] = decode(config[13])[::-1]
		conf["Active X Key"] = decode(config[14])[::-1]
		conf["Registry Key"] = decode(config[15])[::-1]
		conf["Active X Run"] = decode(config[16])[::-1]
		conf["Registry Run"] = decode(config[17])[::-1]
		conf["Safe Mode Startup"] = decode(config[18])[::-1]
		conf["Inject winlogon.exe"] = decode(config[19])[::-1]
		conf["Install Name"] = decode(config[20])[::-1]
		conf["Install Path"] = decode(config[21])[::-1]
		conf["Campaign Name"] = decode(config[22])[::-1]
		conf["Campaign Group"] = decode(config[23])[::-1]
	return conf
	
		
#Helper Functions Go Here

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
			if str(entry.name) == "SETTINGS":
				data_rva = entry.directory.entries[0].data.struct.OffsetToData
				size = entry.directory.entries[0].data.struct.Size
				data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
				config = data.split('}')
				return config
	except:
		return None		

def decode(string):
	result = ""
	for i in range(0,len(string)):
		a = ord(string[i])
		result += chr(a-1)
	return result
	

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
