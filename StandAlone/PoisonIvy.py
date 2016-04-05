#!/usr/bin/env python
'''
PoisonIvy Rat Config Decoder
'''


__description__ = 'PoisonIvy Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/04/10'

#Standard Imports Go Here
import os
import sys
import string
from struct import unpack
from optparse import OptionParser

#Non Standard Imports


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
	# Split to get start of Config
	one = firstSplit(data)
	if one == None:
		return None
	# If the split works try to walk the strings
	two = dataWalk(one)
	# lets Process this and format the config
	three = configProcess(two)
	return three
	
		
#Helper Functions Go Here
def calcLength(byteStr):
	try:
		return unpack("<H", byteStr)[0]
	except:
		return None

def stringPrintable(line):
	return filter(lambda x: x in string.printable, line)

def firstSplit(data):
	splits = data.split('Software\\Microsoft\\Active Setup\\Installed Components\\')
	if len(splits) == 2:
		return splits[1]
	else:
		return None
		
def bytetohex(byteStr):
	return ''.join(["%02X" % ord(x) for x in byteStr]).strip()

	
def dataWalk(splitdata):
	# Byte array to make things easier
	stream = bytearray(splitdata)
	# End of file for our while loop
	EOF = len(stream)
	# offset to track position
	offset = 0
	this = []
	maxCount = 0
	while offset < EOF and maxCount < 22:
		try:
			length = calcLength(str(stream[offset+2:offset+4]))
			temp = []
			for i in range(offset+4, offset+4+length):
				temp.append(chr(stream[i]))
			dataType = bytetohex(splitdata[offset]+splitdata[offset+1])
			this.append((dataType,''.join(temp)))
			offset += length+4
			maxCount += 1
		except:
			return this
	return this

def domainWalk(rawStream):
	domains = ''
	offset = 0
	stream = bytearray(rawStream)
	while offset < len(stream):
		length = stream[offset]
		temp = []
		for i in range(offset+1, offset+1+length):
			temp.append(chr(stream[i]))
		domain = ''.join(temp)

		rawPort = rawStream[offset+length+2:offset+length+4]
		port = calcLength(rawPort)
		offset += length+4
		domains += "{0}:{1}|".format(domain, port)
	return domains	


def configProcess(rawConfig):
	configDict = {"Campaign ID" : "" , "Group ID" : "" , "Domains" : "" , "Password" : "" , "Enable HKLM" : "" , "HKLM Value" : "" , "Enable ActiveX" : "" , "ActiveX Key" : "" , "Flag 3" : "" , "Inject Exe" : "" , "Mutex" : "" , "Hijack Proxy" : "" , "Persistent Proxy" : "" , "Install Name" : "" , "Install Path" : "" , "Copy to ADS" : "" , "Melt" : "" , "Enable Thread Persistence" : "" , "Inject Default Browser" : "" , "Enable KeyLogger" : ""}
	for x in rawConfig:
		if x[0] == 'FA0A':
			configDict["Campaign ID"] = stringPrintable(x[1])
		if x[0] == 'F90B':
			configDict["Group ID"] = stringPrintable(x[1])
		if x[0] == '9001':
			configDict["Domains"] = domainWalk(x[1])
		if x[0] == '4501':
			configDict["Password"] = stringPrintable(x[1])
		if x[0] == '090D':
			configDict["Enable HKLM"] = bytetohex(x[1])
		if x[0] == '120E':
			configDict["HKLM Value"] = stringPrintable(x[1])
		if x[0] == 'F603':
			configDict["Enable ActiveX"] = bytetohex(x[1])
		if x[0] == '6501':
			configDict["ActiveX Key"] = stringPrintable(x[1])
		if x[0] == '4101':
			configDict["Flag 3"] = bytetohex(x[1])
		if x[0] == '4204':
			configDict["Inject Exe"] = stringPrintable(x[1])
		if x[0] == 'Fb03':
			configDict["Mutex"] = stringPrintable(x[1])
		if x[0] == 'F40A':
			configDict["Hijack Proxy"] = bytetohex(x[1])
		if x[0] == 'F50A':
			configDict["Persistent Proxy"] = bytetohex(x[1])
		if x[0] == '2D01':
			configDict["Install Name"] = stringPrintable(x[1])
		if x[0] == 'F703':
			configDict["Install Path"] = stringPrintable(x[1])
		if x[0] == '120D':
			configDict["Copy to ADS"] = bytetohex(x[1])
		if x[0] == 'F803':
			configDict["Melt"] = bytetohex(x[1])
		if x[0] == 'F903':
			configDict["Enable Thread Persistence"] = bytetohex(x[1])
		if x[0] == '080D':
			configDict["Inject Default Browser"] = bytetohex(x[1])
		if x[0] == 'FA03':
			configDict["Enable KeyLogger"] = bytetohex(x[1])
	return configDict
	
#Recursive Function Goes Here

def runRecursive(folder, output):
	counter1 = 0
	counter2 = 0
	print "[+] Writing Configs to File {0}".format(output)
	with open(output, 'a+') as out:
		#This line will need changing per Decoder
		out.write("Filename,Campaign ID, Group ID, Domains, Password, Enable HKLM, HKLM Value, Enable ActiveX, ActiveX Value, Flag 3, Inject Exe, Mutex, Hijack Proxy, Persistant Proxy, Install Name, Install Path, Copy To ADS, Mely, Enable Thread Persistance, Inject Default Browser, Enable Keylogger\n")	
		for server in os.listdir(folder):
			fileData = open(os.path.join(folder,server), 'rb').read()
			configOut = run(fileData)
			if configOut != None:
				#This line will need changing per Decoder
				out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20}\n'.format(server, configOut["Campaign ID"],configOut["Group ID"],configOut["Domains"],configOut["Password"],configOut["Enable HKLM"],configOut["HKLM Value"],configOut["Enable ActiveX"],configOut["ActiveX Key"],configOut["Flag 3"],configOut["Inject Exe"],configOut["Mutex"],configOut["Hijack Proxy"],configOut["Persistent Proxy"],configOut["Install Name"],configOut["Install Path"],configOut["Copy to ADS"],configOut["Melt"],configOut["Enable Thread Persistence"],configOut["Inject Default Browser"],configOut["Enable KeyLogger"]))
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
