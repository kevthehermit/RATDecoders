#!/usr/bin/env python
'''
DarkRAT Config Decoder
'''

__description__ = 'DarkRAT Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/04/10'

#Standard Imports Go Here
import os
import sys
import string
from optparse import OptionParser

#Non Standard Imports


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
	Config = {}
	rawConfig = data.split("@1906dark1996coder@")
	if len(rawConfig) > 3:
		Config["Domain"] = rawConfig[1][7:-1]#
		Config["AutoRun"] = rawConfig[2]#
		Config["USB Spread"] = rawConfig[3]#
		Config["Hide Form"] = rawConfig[4]#
		Config["Msg Box Title"] = rawConfig[6]#
		Config["Msg Box Text"] = rawConfig[7]#
		Config["Timer Interval"] = rawConfig[8]#
		if rawConfig[5] == 4:
			Config["Msg Box Type"] = "Information"
		elif rawConfig[5] == 2:
			Config["Msg Box Type"] = "Question"
		elif rawConfig[5] == 3:
			Config["Msg Box Type"] = "Exclamation"
		elif rawConfig[5] == 1:
			Config["Msg Box Type"] = "Critical"
		else:
			Config["Msg Box Type"] = "None"
		return Config
		
#Helper Functions Go Here



#Recursive Function Goes Here

def runRecursive(folder, output):
	counter1 = 0
	counter2 = 0
	print "[+] Writing Configs to File {0}".format(output)
	with open(output, 'a+') as out:
		#This line will need changing per Decoder
		out.write("Filename,Domain, AutoRun, USB Spread, Hide Form, MsgBox Title, MsgBox Text, Timer Interval, Msg Box Type\n")	
		for server in os.listdir(folder):
			fileData = open(os.path.join(folder,server), 'rb').read()
			configOut = run(fileData)
			if configOut != None:
				#This line will need changing per Decoder
				out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8}\n'.format(server, configOut["Domain"],configOut["AutoRun"],configOut["USB Spread"],configOut["Hide Form"],configOut["Msg Box Title"],configOut["Msg Box Text"],configOut["Timer Interval"],configOut["Msg Box Type"]))
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
