#!/usr/bin/env python
'''
ArCom Rat Config Decoder
'''


__description__ = 'ArCom Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/04/10'

#Imports Go Here
import os
import sys
import base64
import string
from optparse import OptionParser
try:
	from Crypto.Cipher import Blowfish
except ImportError:
	print "[+] Couldn't Import Cipher, try 'sudo pip install pycrypto'"


# Main Decode Function Goes Here

key = "CVu3388fnek3W(3ij3fkp0930di"
def run(data):
	dict = {}
	try:
		config = data.split("\x18\x12\x00\x00")[1].replace('\xA3\x24\x25\x21\x64\x01\x00\x00','')
		configdecode = base64.b64decode(config)
		configDecrypt = decryptBlowfish(key, configdecode)
		parts = configDecrypt.split('|')
		if len(parts) > 3:
			dict["Domain"] = parts[0]
			dict["Port"] = parts[1]
			dict["Install Path"] = parts[2]
			dict["Install Name"] = parts[3]
			dict["Startup Key"] = parts[4]
			dict["Campaign ID"] = parts[5]
			dict["Mutex Main"] = parts[6]
			dict["Mutex Per"] = parts[7]
			dict["YPER"] = parts[8]
			dict["YGRB"] = parts[9]
			dict["Mutex Grabber"] = parts[10]
			dict["Screen Rec Link"] = parts[11]
			dict["Mutex 4"] = parts[12]
			dict["YVID"] = parts[13]
			dict["YIM"] = parts[14]
			dict["NO"] = parts[15]
			dict["Smart Broadcast"] = parts[16]
			dict["YES"] = parts[17]
			dict["Plugins"] = parts[18]
			dict["Flag1"] = parts[19]
			dict["Flag2"] = parts[20]
			dict["Flag3"] = parts[21]
			dict["Flag4"] = parts[22]
			dict["WebPanel"] = parts[23]
			dict["Remote Delay"] = parts[24]
			return dict
	except:
		return None
		
#Helper Functions Go Here

def decryptBlowfish(key, data):
	cipher = Blowfish.new(key)
	return cipher.decrypt(data)

#Recursive Function Goes Here

def runRecursive(folder, output):
	counter1 = 0
	counter2 = 0
	print "[+] Writing Configs to File {0}".format(output)
	with open(output, 'a+') as out:
		out.write("Filename,Domain, Port, Install Path, Install Name, StartupKey, Campaign ID, Mutex Main, Mutex Per, YPER, YGRB, Mutex Grabber, Screen Rec Link, Mutex 4, YVID, YIM, No, Smart, Plugins, Flag1, Flag2, Flag3, Flag4, WebPanel, Remote Delay\n")	
		for server in os.listdir(folder):
			fileData = open(os.path.join(folder,server), 'rb').read()
			dict = run(fileData)
			if dict != None:
				out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21},{22},{23},{24},{25}\n'.format(server, dict["Domain"],dict["Port"],dict["Install Path"],dict["Install Name"],dict["Startup Key"],dict["Campaign ID"],dict["Mutex Main"],dict["Mutex Per"],dict["YPER"],dict["YGRB"],dict["Mutex Grabber"],dict["Screen Rec Link"],dict["Mutex 4"],dict["YVID"],dict["YIM"],dict["NO"],dict["Smart Broadcast"],dict["YES"],dict["Plugins"],dict["Flag1"],dict["Flag2"],dict["Flag3"],dict["Flag4"],dict["WebPanel"],dict["Remote Delay"]))
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
