#!/usr/bin/env python
'''
BlackShades RAT Decoder

Original Script by Brian Wallace (@botnet_hunter)


'''

__description__ = 'DarkComet Rat Config Extractor\nOriginal Script by Brian Wallace (@botnet_hunter)'
__author__ = 'Kevin Breen http://techanarchy.net'
__OrigionalCode__ = 'v1.0.0 by Brian Wallace (@botnet_hunter)'
__version__ = '0.1'
__date__ = '2014/05/23'

import os
import sys
import string
import re
from optparse import OptionParser

prng_seed = 0


def is_valid_config(config):
    if config[:3] != "\x0c\x0c\x0c":
        return False
    if config.count("\x0C\x0C\x0C") < 15:
        return False
    return True


def get_next_rng_value():
    global prng_seed
    prng_seed = ((prng_seed * 1140671485 + 12820163) & 0xffffff)
    return prng_seed / 65536

def decrypt_configuration(hex):
    global prng_seed
    ascii = hex.decode('hex')
    tail = ascii[0x20:]

    pre_check = []
    for x in xrange(3):
        pre_check.append(ord(tail[x]) ^ 0x0c)

    for x in xrange(0xffffff):
        prng_seed = x
        if get_next_rng_value() != pre_check[0] or get_next_rng_value() != pre_check[1] or get_next_rng_value() != pre_check[2]:
            continue
        prng_seed = x
        config = "".join((chr(ord(c) ^ int(get_next_rng_value())) for c in tail))
        if is_valid_config(config):
            return config.split("\x0c\x0c\x0c")
    return None
 

def config_extract(raw_data):
    config_pattern = re.findall('[0-9a-fA-F]{154,}', raw_data)
    for s in config_pattern:
        if (len(s) % 2) == 1:
            s = s[:-1]
            return s

def config_parser(config):
    config_dict = {}
    config_dict['Domain'] = config[1]
    config_dict['Client Control Port'] = config[2]
    config_dict['Client Transfer Port'] = config[3]
    config_dict['Campaign ID'] = config[4]
    config_dict['File Name'] = config[5]
    config_dict['Install Path'] = config[6]
    config_dict['Registry Key'] = config[7]
    config_dict['ActiveX Key'] = config[8]
    config_dict['Install Flag'] = config[9]
    config_dict['Hide File'] = config[10]
    config_dict['Melt File'] = config[11]
    config_dict['Delay'] = config[12]
    config_dict['USB Spread'] = config[13]
    config_dict['Mutex'] = config[14]
    config_dict['Log File'] = config[15]
    config_dict['Folder Name'] = config[16]
    config_dict['Smart DNS'] = config[17]
    config_dict['Protect Process'] = config[18]
    return config_dict
        
def run(data):
    raw_config = config_extract(data)
    config = decrypt_configuration(raw_config)
    if config is not None and len(config) > 15:
        sorted_config = config_parser(config)
        return sorted_config
    return None


#Recursive Function Goes Here

def runRecursive(folder, output):
	counter1 = 0
	counter2 = 0
	print "[+] Writing Configs to File {0}".format(output)
	with open(output, 'a+') as out:
		#This line will need changing per Decoder
		out.write("File Name, Campaign ID, Domain, Transfer Port, Control Port, File Name, Install Path, Registry Key, ActiveX Key, Install Flag, Hide File, Melt File, Delay, USB Spread, Mutex, Log File, Folder Name, Smart DNS, Protect Process\n")	
		for server in os.listdir(folder):
			fileData = open(os.path.join(folder,server), 'rb').read()
			configOut = run(fileData)
			if configOut != None:
				#This line will need changing per Decoder
				out.write('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18}\n'.format(server, configOut["Campaign ID"],configOut["Domain"],configOut["Client Transfer Port"],configOut["Client Control Port"],configOut["File Name"],configOut["Install Path"],configOut["Registry Key"],configOut["ActiveX Key"],configOut["Install Flag"],configOut["Hide File"],configOut["Melt File"],configOut["Delay"],configOut["USB Spread"],configOut["Mutex"],configOut["Log File"],configOut["Folder Name"],configOut["Smart DNS"],configOut["Protect Process"]))
				counter1 += 1
			counter2 += 1
	print "[+] Decoded {0} out of {1} Files".format(counter1, counter2)
	return "Complete"


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
                sys.exit()
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
