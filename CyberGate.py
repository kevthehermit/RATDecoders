#!/usr/bin/env python
'''
CyberGate Rat Config Decoder
'''


__description__ = 'CyberGate Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net http://malwareconfig.com'
__version__ = '0.1'
__date__ = '2014/04/10'

#Standard Imports Go Here
import os
import sys
import string
from optparse import OptionParser

#Non Standard Imports
try:
	import pefile
except ImportError:
	print "[+] Couldn't Import Cipher, try 'sudo pip install pefile'"


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
	Config = {}
	rawConfig = configExtract(data)
	if rawConfig != None:
		if len(rawConfig) > 20:
			domains = ""
			ports = ""
			#Config sections 0 - 19 contain a list of Domains and Ports
			for x in range(0,19):
				if len(rawConfig[x]) > 1:
					domains += xorDecode(rawConfig[x]).split(':')[0]
					domains += "|"
					ports += xorDecode(rawConfig[x]).split(':')[1]
					ports += "|"				
			Config["Domain"] = domains
			Config["Port"] = ports
			Config["ServerID"] = xorDecode(rawConfig[20])
			Config["Password"] = xorDecode(rawConfig[21])
			Config["Install Flag"] = xorDecode(rawConfig[22])
			Config["Install Directory"] = xorDecode(rawConfig[25])
			Config["Install File Name"] = xorDecode(rawConfig[26])
			Config["Active X Startup"] = xorDecode(rawConfig[27])
			Config["REG Key HKLM"] = xorDecode(rawConfig[28])
			Config["REG Key HKCU"] = xorDecode(rawConfig[29])
			Config["Enable Message Box"] = xorDecode(rawConfig[30])
			Config["Message Box Icon"] = xorDecode(rawConfig[31])
			Config["Message Box Button"] = xorDecode(rawConfig[32])
			Config["Install Message Title"] = xorDecode(rawConfig[33])
			Config["Install Message Box"] = xorDecode(rawConfig[34]).replace('\r\n', ' ')
			Config["Activate Keylogger"] = xorDecode(rawConfig[35])
			Config["Keylogger Backspace = Delete"] = xorDecode(rawConfig[36])
			Config["Keylogger Enable FTP"] = xorDecode(rawConfig[37])
			Config["FTP Address"] = xorDecode(rawConfig[38])
			Config["FTP Directory"] = xorDecode(rawConfig[39])
			Config["FTP UserName"] = xorDecode(rawConfig[41])
			Config["FTP Password"] = xorDecode(rawConfig[42])
			Config["FTP Port"] = xorDecode(rawConfig[43])
			Config["FTP Interval"] = xorDecode(rawConfig[44])
			Config["Persistance"] = xorDecode(rawConfig[59])
			Config["Hide File"] = xorDecode(rawConfig[60])
			Config["Change Creation Date"] = xorDecode(rawConfig[61])
			Config["Mutex"] = xorDecode(rawConfig[62])		
			Config["Melt File"] = xorDecode(rawConfig[63])
			Config["CyberGate Version"] = xorDecode(rawConfig[67])		
			Config["Startup Policies"] = xorDecode(rawConfig[69])
			Config["USB Spread"] = xorDecode(rawConfig[70])
			Config["P2P Spread"] = xorDecode(rawConfig[71])
			Config["Google Chrome Passwords"] = xorDecode(rawConfig[73])
			Config["Process Injection"] = "Disabled"
			if xorDecode(rawConfig[57]) == 0 or xorDecode(rawConfig[57]) == None:
				Config["Process Injection"] = "Disabled"
			elif xorDecode(rawConfig[57]) == 1:
				Config["Process Injection"] = "Default Browser"
			elif xorDecode(rawConfig[57]) == 2:
				Config["Process Injection"] = xorDecode(rawConfig[58])
		else:
			return None
		return Config
	
		
#Helper Functions Go Here

def xorDecode(data):
	key = 0xBC
	encoded = bytearray(data)
	for i in range(len(encoded)):
		encoded[i] ^= key
	return filter(lambda x: x in string.printable, str(encoded))

def configExtract(rawData):
	try:
		pe = pefile.PE(data=rawData)

		try:
		  rt_string_idx = [
		  entry.id for entry in 
		  pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
		except ValueError, e:
			return None
		except AttributeError, e:
			return None

		rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

		for entry in rt_string_directory.directory.entries:
			if str(entry.name) == "XX-XX-XX-XX" or str(entry.name) == "CG-CG-CG-CG":
				data_rva = entry.directory.entries[0].data.struct.OffsetToData
				size = entry.directory.entries[0].data.struct.Size
				data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
				config = data.split('####@####')
				return config
	except:
		return None		


#Recursive Function Goes Here

def runRecursive(folder, output):
	counter1 = 0
	counter2 = 0
	print "[+] Writing Configs to File {0}".format(output)
	with open(output, 'a+') as out:
		#This line will need changing per Decoder
		out.write("Filename,Domains, Ports, Campaign ID, Password, Install Flag, Install Dir, Install File Name, ActiveX Key, HKLM Key, HKCU Key, Enable MessageBox, Message Box Icon, Mesage Box Button, Message Title, Message Box Text, Enable Keylogger, KeyLogger Backspace, Keylogger FTP, FTP Address, FTP UserName, FTP Password, FTP Port, FTP Interval, Persistnace, Hide File, Change Creation Date, Mutex, Melt File, Verison, Startup Polocies, USB Spread, P2P Spread, Google Chrome Passwords, Process Injection\n")	
		for server in os.listdir(folder):
			fileData = open(os.path.join(folder,server), 'rb').read()
			Config = run(fileData)
			if Config != None:
				#This line will need changing per Decoder
				out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21},{22},{23},{24},{25},{26},{27},{28},{29},{30},{31},{32},{33},{34},{35}\n'.format(server, Config["Domain"],Config["Port"],Config["ServerID"],Config["Password"],Config["Install Flag"],Config["Install Directory"],Config["Install File Name"],Config["Active X Startup"],Config["REG Key HKLM"],Config["REG Key HKCU"],Config["Enable Message Box"],Config["Message Box Icon"],Config["Message Box Button"],Config["Install Message Title"],Config["Install Message Box"],Config["Activate Keylogger"],Config["Keylogger Backspace = Delete"],Config["Keylogger Enable FTP"],Config["FTP Address"],Config["FTP Directory"],Config["FTP UserName"],Config["FTP Password"],Config["FTP Port"],Config["FTP Interval"],Config["Persistance"],Config["Hide File"],Config["Change Creation Date"],Config["Mutex"],Config["Melt File"],Config["CyberGate Version"],Config["Startup Policies"],Config["USB Spread"],Config["P2P Spread"],Config["Google Chrome Passwords"],Config["Process Injection"]))
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
