#!/usr/bin/env python
'''
SmallNet Config Decoder
'''

__description__ = 'SmallNet Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net'
__version__ = '0.1'
__date__ = '2014/03/15'

import sys
import string
from optparse import OptionParser

def run(data):
	if "!!<3SAFIA<3!!" in data:
		config = version52(data)
		return config
	elif "!!ElMattadorDz!!" in data:
		config = version5(data)
		return config
	else:
		return None
	

def version52(data):
	dict = {}
	config = data.split("!!<3SAFIA<3!!")
	dict["Domain"] = config[1]
	dict["Port"] = config[2]
	dict["Disbale Registry"] = config[3]
	dict["Disbale TaskManager"] = config[4]
	dict["Install Server"] = config[5]
	dict["Registry Key"] = config[8]
	dict["Install Name"] = config[9]
	dict["Disbale UAC"] = config[10]
	dict["Anti-Sandboxie"] = config[13]
	dict["Anti-Anubis"] = config[14]
	dict["Anti-VirtualBox"] = config[15]
	dict["Anti-VmWare"] = config[16]
	dict["Anti-VirtualPC"] = config[17]
	dict["ServerID"] = config[18]
	dict["USB Spread"] = config[19]
	dict["P2P Spread"] = config[20]
	dict["RAR Spread"] = config[21]
	dict["MSN Spread"] = config[22]
	dict["Yahoo Spread"] = config[23]
	dict["LAN Spread"] = config[24]
	dict["Disbale Firewall"] = config[25] #Correct
	dict["Delay Execution MiliSeconds"] = config[26]
	dict["Attribute Read Only"] = config[27]
	dict["Attribute System File"] = config[28]
	dict["Attribute Hidden"] = config[29]
	dict["Attribute Compressed"] = config[30]
	dict["Attribute Temporary"] = config[31]
	dict["Attribute Archive"] = config[32]
	dict["Modify Creation Date"] = config[33]
	dict["Modified Creation Data"] = config[34]
	dict["Thread Persistance"] = config[35]
	dict["Anti-ZoneAlarm"] = config[36]
	dict["Anti-SpyTheSpy"] = config[37]
	dict["Anti-NetStat"] = config[38]
	dict["Anti-TiGeRFirewall"] = config[39]
	dict["Anti-TCPview"] = config[40]
	dict["Anti-CurrentPorts"] = config[41]
	dict["Anti-RogueKiller"] = config[42]
	dict["Enable MessageBox"] = config[43]
	dict["MessageBox Message"] = config[44]
	dict["MessageBox Icon"] = config[45]
	dict["MessageBox Buttons"] = config[46]
	dict["MessageBox Title"] = config[47]	
	if config[6] == 1:
		dict["Install Path"] = "Temp"
	if config[7] == 1:
		dict["Install Path"] = "Windows"
	if config[11] == 1:
		dict["Install Path"] = "System32"
	if config[12] == 1:
		dict["Install Path"] = "Program Files"
	return dict


def version5(data):
	dict = {}
	config = data.split("!!ElMattadorDz!!")
	dict["Domain"] = config[1] #Correct
	dict["Port"] = config[2] #Correct
	dict["Disable Registry"] = config[3]
	dict["Disbale TaskManager"] = config[4] #Correct
	dict["Install Server"] = config[5] #Correct
	dict["Registry Key"] = config[8] #Correct
	dict["Install Name"] = config[9] #Correct
	dict["Disbale UAC"] = config[10]
	dict["Anti-Sandboxie"] = config[13]
	dict["Anti-Anubis"] = config[14]
	dict["Anti-VirtualBox"] = config[15]
	dict["Anti-VmWare"] = config[16]
	dict["Anti-VirtualPC"] = config[17]
	dict["ServerID"] = config[18] # Correct
	dict["USB Spread"] = config[19] #Correct
	dict["P2P Spread"] = config[20] #Correct
	dict["RAR Spread"] = config[21]
	dict["MSN Spread"] = config[22]
	dict["Yahoo Spread"] = config[23]
	dict["LAN Spread"] = config[24]
	dict["Disbale Firewall"] = config[25] #Correct
	dict["Delay Execution MiliSeconds"] = config[26] #Correct
	if config[6] == 1: #Correct
		dict["Install Path"] = "Temp"
	if config[7] == 1: #Correct
		dict["Install Path"] = "Windows" 
	if config[11] == 1: #Correct
		dict["Install Path"] = "System32"
	if config[12] == 1: #Correct
		dict["Install Path"] = "Program Files"
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