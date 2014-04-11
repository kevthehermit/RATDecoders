#!/usr/bin/env python
'''
CyberGate Config Decoder
'''

__description__ = 'CyberGate Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net'
__version__ = '0.1'
__date__ = '2014/03/15'

import sys
import string
from optparse import OptionParser
import pype32


def run(rawData):
	#try:
		rawconfig = rawData.split("abccba")
		if len(rawconfig) > 1:
			print "Running Abccba"
			dict = oldversions(rawconfig)
		else:
			print "Running pype32"
			pe = pype32.PE(data=rawData) 
			rawConfig = getStream(pe)
			if rawConfig.startswith("bute"): # workaround for an error in pype32 will still work when fixed
				rawConfig = rawConfig[8:]
			dict = parseConfig(rawConfig)
		#except:
			#return None
		print dict
		

		
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
 
#Walk the User Strings and create a list of individual strings
def parseConfig(rawConfig):
	stringList = []
	offset = 1
	config = bytearray(rawConfig)
	while offset < len(config):
		length = int(config[offset])
		that = config[offset+1:offset+int(length)]
		stringList.append(str(that.replace("\x00", "")))
		offset += int(length+1)
	print stringList
	dict = {}
	for i in range(0,60):
		dict["Domain"] = stringList[37]
		dict["Port"] = stringList[39]
		dict["Campaign Name"] = stringList[38]
		dict["FolderName"] = stringList[41]
		dict["Exe Name"] = stringList[40]
		dict["Install Folder"] = stringList[44]
	return dict
	
def oldversions(config):
	dict = {}
	if len(config) == 48:
		dict["Version"] = "V0.2.6"
		for i in range(1, len(config)):
			dict["Domain"] = config[1] #
			dict["Port"] = config[2] #
			dict["Campaign Name"] = config[3] #
			dict["Dan Option"] = config[5] #
			dict["Startup Name"] = config[7] #
			dict["Password"] = config[9] #
			dict["Anti Kill Server"] = config[10] #
			dict["USB Spread / lnk"] = config[11]
			dict["Anti Process Explorer"] = config[12]
			dict["Anti Process Hacker"] = config[13]
			dict["Anti ApateDNS"] = config[14]
			dict["Anti MalwareBytes"] = config[15]
			dict["Anti AntiLogger"] = config[16]
			dict["Block Virus Total"] = config[17] #
			dict["Mutex"] = config[18] #
			dict["Persistance"] = config[19] #
			dict["SpyGate Key"] = config[20]
			dict["Startup Folder"] = config[21] #
			dict["Anti Avira"] = config[23]
			dict["USB Spread / exe"] = config[24]
			# 25 if statement below
			dict["Install Folder1"] = config[26] #
			dict["StartUp Name"] = config[27] #
			dict["Melt After Run"] = config[28] #
			dict["Hide After Run"] = config[29] #
			#dict[""] = config[30]
			#dict[""] = config[31]
			#dict[""] = config[32]
			dict["Install Folder2"] = config[33] #
			# 34 and 35 in if statement below
			dict["Install Folder3"] = config[36]
			#dict[""] = config[37]
			dict["Anti SbieCtrl"] = config[38]
			dict["Anti SpyTheSpy"] = config[39]
			dict["Anti SpeedGear"] = config[40]
			dict["Anti Wireshark"] = config[41]
			dict["Anti IPBlocker"] = config[42]
			dict["Anti Cports"] = config[43]
			dict["Anti AVG"] = config[44]
			dict["Anti OllyDbg"] = config[45]
			dict["Anti X Netstat"] = config[46]
			#dict["Anti Keyscrambler"] = config[47]
				
		if config[25] == "True":
			dict["Application Data Folder"] = "True"
		else:
			dict["Application Data Folder"] = "False"
			
		if config[34] == "True":
			dict["Templates Folder"] = "True"
		else:
			dict["Templates Folder"] = "False"
			
		if config[35] == "True":
			dict["Programs Folder"] = "True"
		else:
			dict["Programs Folder"] = "False"
	elif len(config) == 18:
		dict["Version"] = "V2.0"
		for i in range(1, len(config)):
			print i, config[i]
			dict["Domain"] = config[1] #
			dict["Port"] = config[2] #
			dict["Campaign Name"] = config[3] #
			dict["Dan Option"] = config[5] #
			dict["Add To Startup"] = config[5] #
			dict["Startup Key"] = config[7] #
			dict["Password"] = config[9] #
			dict["Anti Kill Server"] = config[10]  #
			dict["USB Spread"] = config[11] #
			dict["Kill Process Explorer"] = config[12] #
			dict["Anti Process Hacker"] = config[13] #
			dict["Anti ApateDNS"] = config[14]
			dict["Anti MalwareBytes"] = config[15]
			dict["Anti AntiLogger"] = config[16]
			dict["Block Virus Total"] = config[17]
	else:
		return None
	return dict
	
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