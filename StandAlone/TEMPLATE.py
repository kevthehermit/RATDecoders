#!/usr/bin/env python
'''
ArCom Rat Config Decoder
'''


__description__ = 'ArCom Rat Config Extractor'
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
	from Crypto.Cipher import Blowfish
except ImportError:
	print "[+] Couldn't Import Cipher, try 'sudo pip install pycrypto'"


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
	
	pass
	
		
#Helper Functions Go Here



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
			configOut = run(fileData)
			if configOut != None:
				#This line will need changing per Decoder
				out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21},{22},{23},{24},{25}\n'.format(server, configOut["Domain"],configOut["Port"],configOut["Install Path"],configOut["Install Name"],configOut["Startup Key"],configOut["Campaign ID"],configOut["Mutex Main"],configOut["Mutex Per"],configOut["YPER"],configOut["YGRB"],configOut["Mutex Grabber"],configOut["Screen Rec Link"],configOut["Mutex 4"],configOut["YVID"],configOut["YIM"],configOut["NO"],configOut["Smart Broadcast"],configOut["YES"],configOut["Plugins"],configOut["Flag1"],configOut["Flag2"],configOut["Flag3"],configOut["Flag4"],configOut["WebPanel"],configOut["Remote Delay"]))
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
