#!/usr/bin/env python
'''
Greame Rat Config Decoder
'''


__description__ = 'Greame Rat Config Extractor'
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
	print "[+] Couldn't Import pefile. Try 'sudo pip install pefile'"


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
	finalConfig = {}
	config = configExtract(data)
	if config != None and len(config) > 20:
		domains = ""
		ports = ""
		#Config sections 0 - 19 contain a list of Domains and Ports
		for x in range(0,19):
			if len(config[x]) > 1:
				domains += xorDecode(config[x]).split(':')[0]
				domains += "|"
				ports += xorDecode(config[x]).split(':')[1]
				ports += "|"
			
		finalConfig["Domain"] = domains
		finalConfig["Port"] = ports
		finalConfig["ServerID"] = xorDecode(config[20])
		finalConfig["Password"] = xorDecode(config[21])
		finalConfig["Install Flag"] = xorDecode(config[22])
		finalConfig["Install Directory"] = xorDecode(config[25])
		finalConfig["Install File Name"] = xorDecode(config[26])
		finalConfig["Active X Startup"] = xorDecode(config[27])
		finalConfig["REG Key HKLM"] = xorDecode(config[28])
		finalConfig["REG Key HKCU"] = xorDecode(config[29])
		finalConfig["Enable Message Box"] = xorDecode(config[30])
		finalConfig["Message Box Icon"] = xorDecode(config[31])
		finalConfig["Message Box Button"] = xorDecode(config[32])
		finalConfig["Install Message Title"] = xorDecode(config[33])
		finalConfig["Install Message Box"] = xorDecode(config[34]).replace('\r\n', ' ')
		finalConfig["Activate Keylogger"] = xorDecode(config[35])
		finalConfig["Keylogger Backspace = Delete"] = xorDecode(config[36])
		finalConfig["Keylogger Enable FTP"] = xorDecode(config[37])
		finalConfig["FTP Address"] = xorDecode(config[38])
		finalConfig["FTP Directory"] = xorDecode(config[39])
		finalConfig["FTP UserName"] = xorDecode(config[41])
		finalConfig["FTP Password"] = xorDecode(config[42])
		finalConfig["FTP Port"] = xorDecode(config[43])
		finalConfig["FTP Interval"] = xorDecode(config[44])
		finalConfig["Persistance"] = xorDecode(config[59])
		finalConfig["Hide File"] = xorDecode(config[60])
		finalConfig["Change Creation Date"] = xorDecode(config[61])
		finalConfig["Mutex"] = xorDecode(config[62])		
		finalConfig["Melt File"] = xorDecode(config[63])		
		finalConfig["Startup Policies"] = xorDecode(config[69])
		finalConfig["USB Spread"] = xorDecode(config[70])
		finalConfig["P2P Spread"] = xorDecode(config[71])
		finalConfig["Google Chrome Passwords"] = xorDecode(config[73])		
		if xorDecode(config[57]) == 0:
			finalConfig["Process Injection"] = "Disabled"
		elif xorDecode(config[57]) == 1:
			finalConfig["Process Injection"] = "Default Browser"
		elif xorDecode(config[57]) == 2:
			finalConfig["Process Injection"] = xorDecode(config[58])
		else: finalConfig["Process Injection"] = "None"
	else:
		return None
	print xorDecode(config[33]).encode('hex')
	return finalConfig
	
		
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
			if str(entry.name) == "GREAME":
				data_rva = entry.directory.entries[0].data.struct.OffsetToData
				size = entry.directory.entries[0].data.struct.Size
				data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
				config = data.split('####@####')
				return config
	except:
		return None

def xorDecode(data):
	key = 0xBC
	encoded = bytearray(data)
	for i in range(len(encoded)):
		encoded[i] ^= key
	return filter(lambda x: x in string.printable, str(encoded))


#Recursive Function Goes Here

def runRecursive(folder, output):
	counter1 = 0
	counter2 = 0
	print "[+] Writing Configs to File {0}".format(output)
	with open(output, 'a+') as out:
		#This line will need changing per Decoder
		out.write("Filename,Domains, Ports, Campaign ID, Password, Install Flag, Install Dir, Install File Name, ActiveX Key, HKLM Key, HKCU Key, Enable MessageBox, Message Box Icon, Mesage Box Button, Message Title, Message Box Text, Enable Keylogger, KeyLogger Backspace, Keylogger FTP, FTP Address, FTP UserName, FTP Password, FTP Port, FTP Interval, Persistnace, Hide File, Change Creation Date, Mutex, Melt File, Startup Polocies, USB Spread, P2P Spread, Google Chrome Passwords, Process Injection\n")	
		for server in os.listdir(folder):
			fileData = open(os.path.join(folder,server), 'rb').read()
			finalConfig = run(fileData)
			if finalConfig != None:
				#This line will need changing per Decoder
				out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21},{22},{23},{24},{25},{26},{27},{28},{29},{30},{31},{32},{33},{34}\n'.format(server, finalConfig["Domain"],finalConfig["Port"],finalConfig["ServerID"],finalConfig["Password"],finalConfig["Install Flag"],finalConfig["Install Directory"],finalConfig["Install File Name"],finalConfig["Active X Startup"],finalConfig["REG Key HKLM"],finalConfig["REG Key HKCU"],finalConfig["Enable Message Box"],finalConfig["Message Box Icon"],finalConfig["Message Box Button"],finalConfig["Install Message Title"],finalConfig["Install Message Box"],finalConfig["Activate Keylogger"],finalConfig["Keylogger Backspace = Delete"],finalConfig["Keylogger Enable FTP"],finalConfig["FTP Address"],finalConfig["FTP Directory"],finalConfig["FTP UserName"],finalConfig["FTP Password"],finalConfig["FTP Port"],finalConfig["FTP Interval"],finalConfig["Persistance"],finalConfig["Hide File"],finalConfig["Change Creation Date"],finalConfig["Mutex"],finalConfig["Melt File"],finalConfig["Startup Policies"],finalConfig["USB Spread"],finalConfig["P2P Spread"],finalConfig["Google Chrome Passwords"],finalConfig["Process Injection"]))
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
