#!/usr/bin/env python
'''
njRat Config Decoder
'''


__description__ = 'njRat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/04/10'

#Standard Imports Go Here
import os
import sys
import base64
import string
from optparse import OptionParser

#Non Standard Imports
try:
	import pype32
except ImportError:
	print "[+] Couldn't Import pype32 'https://github.com/crackinglandia/pype32'"


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
	try:
		pe = pype32.PE(data=data) 
		rawConfig = getStream(pe)
		rawConfig = pypefix(rawConfig)
		# Get a list of strings
		stringList = parseStrings(rawConfig)
		#parse the string list
		dict = parseConfig(stringList)
		return dict
	except:
		return None
	
		
#Helper Functions Go Here

# Confirm if there is Net MetaData in the File 
def getStream(pe):
	counter = 0   
	for dir in pe.ntHeaders.optionalHeader.dataDirectory:
		if dir.name.value == "NET_METADATA_DIRECTORY":
			rawConfig = findUSStream(pe, counter)
		else:
			counter += 1
	return rawConfig

# I only want to extract the User Strings Section
def findUSStream(pe, dir):
	for i in range(0,4):
		name = pe.ntHeaders.optionalHeader.dataDirectory[dir].info.netMetaDataStreams[i].name.value
		if name.startswith("#US"):
			return pe.ntHeaders.optionalHeader.dataDirectory[dir].info.netMetaDataStreams[i].info
		else:
			return None

#Walk the User Strings and create a list of individual strings
def parseStrings(rawConfig):
	stringList = []
	offset = 1
	config = bytearray(rawConfig)
	while offset < len(config):
		length = int(config[offset])
		that = config[offset+1:offset+int(length)]
		stringList.append(str(that.replace("\x00", "")))
		offset += int(length+1)
	return stringList
			
#Turn the strings in to a python Dict
def parseConfig(stringList):
	dict = {}
	if '0.3.5' in stringList:
		dict["Campaign ID"] = base64.b64decode(stringList[3])
		dict["version"] = stringList[4]
		dict["Install Name"] = stringList[0]
		dict["Install Dir"] = stringList[1]
		dict["Registry Value"] = stringList[2]
		dict["Domain"] = stringList[6]
		dict["Port"] = stringList[7]
		dict["Network Separator"] = stringList[8]
		dict["Install Flag"] = stringList[5]
		
	elif '0.3.6' in stringList:
		index = stringList.index('[endof]')
		dict["Campaign ID"] = base64.b64decode(stringList[index+4])
		dict["version"] = stringList[index+5]
		dict["Install Name"] = stringList[index+1]
		dict["Install Dir"] = stringList[index+2]
		dict["Registry Value"] = stringList[index+3]
		dict["Domain"] = stringList[index+7]
		dict["Port"] = stringList[index+8]
		dict["Network Separator"] = stringList[index+9]
		dict["Install Flag"] = stringList[index+10]
		
	elif '0.4.1a' in stringList:
		index = stringList.index('[endof]')
		dict["Campaign ID"] = base64.b64decode(stringList[index+1])
		dict["version"] = stringList[index+2]
		dict["Install Name"] = stringList[index+4]
		dict["Install Dir"] = stringList[index+5]
		dict["Registry Value"] = stringList[index+6]
		dict["Domain"] = stringList[index+7]
		dict["Port"] = stringList[index+8]
		dict["Network Separator"] = stringList[index+10]
		dict["Install Flag"] = stringList[index+3]

		
	elif '0.5.0E' in stringList:
		index = stringList.index('[endof]')
		dict["Campaign ID"] = base64.b64decode(stringList[index-8])
		dict["version"] = stringList[index-7]
		dict["Install Name"] = stringList[index-6]
		dict["Install Dir"] = stringList[index-5]
		dict["Registry Value"] = stringList[index-4]
		dict["Domain"] = stringList[index-3]
		dict["Port"] = stringList[index-2]
		dict["Network Separator"] = stringList[index-1]
		dict["Install Flag"] = stringList[index+3]

		
	elif '0.6.4' in stringList:
		dict["Campaign ID"] = base64.b64decode(stringList[0])
		dict["version"] = stringList[1]
		dict["Install Name"] = stringList[2]
		dict["Install Dir"] = stringList[3]
		dict["Registry Value"] = stringList[4]
		dict["Domain"] = stringList[5]
		dict["Port"] = stringList[6]
		dict["Network Separator"] = stringList[7]
		dict["Install Flag"] = stringList[8]
		
	elif '0.7d' in stringList:
		dict["Campaign ID"] = base64.b64decode(stringList[0])
		dict["version"] = stringList[1]
		dict["Install Name"] = stringList[2]
		dict["Install Dir"] = stringList[3]
		dict["Registry Value"] = stringList[4]
		dict["Domain"] = stringList[5]
		dict["Port"] = stringList[6]
		dict["Network Separator"] = stringList[7]
		dict["Install Flag"] = stringList[8]
		
	else:
		return None
		
	# Really hacky test to check for a valid config.	
	if dict["Install Flag"] == "True" or dict["Install Flag"] == "False" or dict["Install Flag"] == "":
		return dict
	else:
		return None

# theres an error when you try to get the strings section, this trys to fix that.
def pypefix(rawConfig):
	counter = 0
	while counter < 10:
		x = rawConfig[counter]
		if x == '\x00':
			return rawConfig[counter:]
			
		else:
			counter += 1


#Recursive Function Goes Here

def runRecursive(folder, output):
	counter1 = 0
	counter2 = 0
	print "[+] Writing Configs to File {0}".format(output)
	with open(output, 'a+') as out:
		#This line will need changing per Decoder
		out.write("Filename,Campaign ID, Version, Install Name, Install Dir, Registry Value, Domain, Network Seperator, Install Flag\n")	
		for server in os.listdir(folder):
			fileData = open(os.path.join(folder,server), 'rb').read()
			dict = run(fileData)
			if dict != None:
				#This line will need changing per Decoder
				out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},\n'.format(server, dict["Campaign ID"],dict["version"],dict["Install Name"],dict["Install Dir"],dict["Registry Value"],dict["Domain"],dict["Port"],dict["Network Separator"],dict["Install Flag"]))
				counter1 += 1
			counter2 += 1
	print "[+] Decoded {0} out of {1} Files".format(counter1, counter2)
	return "Complete"

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
		if len(args) == 2:
			runRecursive(args[0], args[1])
			sys.exit()
		else:
			print "[+] You need to specify Both Dir to read AND Output File"
			parser.print_help()
			sys.exit()
	
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
