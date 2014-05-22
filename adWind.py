#!/usr/bin/env python
'''
adWind Rat Config Decoder
'''


__description__ = 'adWind Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/04/10'

#Standard Imports Go Here
import os
import sys
import string
import binascii
from zipfile import ZipFile
from cStringIO import StringIO
import xml.etree.ElementTree as ET
from optparse import OptionParser

#Non Standard Imports
try:
	from Crypto.Cipher import ARC4
	from Crypto.Cipher import DES
except ImportError:
	print "[+] Couldn't Import Cipher, try 'sudo pip install pycrypto'"


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):	
	Key = "awenubisskqi"
	newZip = StringIO(data)
	rawConfig = {}
	with ZipFile(newZip, 'r') as zip:
		for name in zip.namelist():
			if name == "config.xml": # contains the encryption key
				# We need two attempts here first try DES for V1 If not try RC4 for V2
				try:
					config = zip.read(name)
					result = DecryptDES(Key[:-4], config)
				except:
					config = zip.read(name)
					result = DecryptRC4(Key, config)								
				xml = filter(lambda x: x in string.printable, result)
				root = ET.fromstring(xml)
				for child in root:
					if child.text.startswith("Adwind RAT"):
						rawConfig["Version"] = child.text
					else:
						rawConfig[child.attrib["key"]] = child.text
				newConfig = sortConfig(rawConfig)
				return newConfig
	
		
#Helper Functions Go Here	


def sortConfig(oldConfig):
	if oldConfig["Version"] == "Adwind RAT v1.0":
		newConfig = {}
		newConfig["Version"] = oldConfig["Version"]
		newConfig["Delay"] = oldConfig["delay"]
		newConfig["Domain"] = oldConfig["dns"]
		newConfig["Install Flag"] = oldConfig["instalar"]
		newConfig["Jar Name"] = oldConfig["jarname"]
		newConfig["Reg Key"] = oldConfig["keyClase"]
		newConfig["Install Folder"] = oldConfig["nombreCarpeta"]
		newConfig["Password"] = oldConfig["password"]
		newConfig["Campaign ID"] = oldConfig["prefijo"]
		newConfig["Port1"] = oldConfig["puerto1"]
		newConfig["Port2"] = oldConfig["puerto2"]
		newConfig["Reg Value"] = oldConfig["regname"]
		print newConfig
		return newConfig

	if oldConfig["Version"] == "Adwind RAT v2.0":
		newConfig = {}
		newConfig["Version"] = oldConfig["Version"]
		newConfig["Delay"] = oldConfig["delay"]
		newConfig["Domain"] = oldConfig["dns"]
		newConfig["Install Flag"] = oldConfig["instalar"]
		newConfig["Reg Key"] = oldConfig["keyClase"]
		newConfig["Password"] = oldConfig["password"]
		newConfig["Campaign ID"] = oldConfig["prefijo"]
		newConfig["Port1"] = oldConfig["puerto"]
		print newConfig
		return newConfig
	
	return oldConfig
		
def DecryptDES(enckey, data):
	cipher = DES.new(enckey, DES.MODE_ECB) # set the ciper
	return cipher.decrypt(data) # decrpyt the data
	
def DecryptRC4(enckey, data):
	cipher = ARC4.new(enckey) # set the ciper
	return cipher.decrypt(data) # decrpyt the data


#Recursive Function Goes Here

def runRecursive(folder, output):
	counter1 = 0
	counter2 = 0
	print "[+] Writing Configs to File {0}".format(output)
	with open(output, 'a+') as out:
		#This line will need changing per Decoder
		out.write("Filename,Domain, Port, Install Path, Install Name, StartupKey, Campaign ID, Mutex Main, Mutex Per, YPER, YGRB, Mutex Grabber, Screen Rec Link, Mutex 4, YVID, YIM, No, Smart, Plugins, Flag1, Flag2, Flag3, Flag4, WebPanel, Remote Delay\n")	
		for server in os.listdir(folder):
			fileData = open(os.path.join(folder,server), 'rb').read()
			config = run(fileData)
			if config != None:
				#This line will need changing per Decoder
				out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21},{22},{23},{24},{25}\n'.format(server, config["Domain"],config["Port"],config["Install Path"],config["Install Name"],config["Startup Key"],config["Campaign ID"],config["Mutex Main"],config["Mutex Per"],config["YPER"],config["YGRB"],config["Mutex Grabber"],config["Screen Rec Link"],config["Mutex 4"],config["YVID"],config["YIM"],config["NO"],config["Smart Broadcast"],config["YES"],config["Plugins"],config["Flag1"],config["Flag2"],config["Flag3"],config["Flag4"],config["WebPanel"],config["Remote Delay"]))
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
