#!/usr/bin/env python
'''
DarkComet Rat Config Decoder
'''

__description__ = 'DarkComet Rat Config Extractor'
__author__ = 'Kevin Breen http://techanarchy.net'
__version__ = '0.1'
__date__ = '2014/03/15'

import sys
import string
from struct import unpack
try:
	import pefile
except ImportError:
	print "Couldnt Import pefile. Try 'sudo pip install pefile'"
from optparse import OptionParser
from binascii import *



def rc4crypt(data, key):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
    
    return ''.join(out)

def v51_data(data, enckey):
	config = {"FWB": "", "GENCODE": "", "MUTEX": "", "NETDATA": "", "OFFLINEK": "", "SID": "", "FTPUPLOADK": "", "FTPHOST": "", "FTPUSER": "", "FTPPASS": "", "FTPPORT": "", "FTPSIZE": "", "FTPROOT": "", "PWD": ""}
	dec = rc4crypt(unhexlify(data), enckey)
	dec_list = dec.split('\n')
	for entries in dec_list[1:-1]:
		key, value = entries.split('=')
		key = key.strip()
		value = value.rstrip()[1:-1]
		clean_value = filter(lambda x: x in string.printable, value)
		config[key] = clean_value
		config["Version"] = enckey[:-4]
	return config

def v3_data(data, key):
	config = {"FWB": "", "GENCODE": "", "MUTEX": "", "NETDATA": "", "OFFLINEK": "", "SID": "", "FTPUPLOADK": "", "FTPHOST": "", "FTPUSER": "", "FTPPASS": "", "FTPPORT": "", "FTPSIZE": "", "FTPROOT": "", "PWD": ""}
	dec = rc4crypt(unhexlify(data), key)
	config[str(entry.name)] = dec
	config["Version"] = enckey[:-4]

	return config

def versionCheck(rawData):
	if "#KCMDDC2#" in rawData:
		return "#KCMDDC2#-890"
		
	elif "#KCMDDC4#" in rawData:
		return "#KCMDDC4#-890"
		
	elif "#KCMDDC42#" in rawData:
		return "#KCMDDC42#-890"

	elif "#KCMDDC42F#" in rawData:
		return "#KCMDDC42F#-890"
		
	elif "#KCMDDC5#" in rawData:
		return "#KCMDDC5#-890"

	elif "#KCMDDC51#" in rawData:
		return "#KCMDDC51#-890"
	else:
		return None

def configExtract(rawData, key):			
	config = {"FWB": "", "GENCODE": "", "MUTEX": "", "NETDATA": "", "OFFLINEK": "", "SID": "", "FTPUPLOADK": "", "FTPHOST": "", "FTPUSER": "", "FTPPASS": "", "FTPPORT": "", "FTPSIZE": "", "FTPROOT": "", "PWD": ""}

	pe = pefile.PE(data=rawData)
	rt_string_idx = [
	entry.id for entry in 
	pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
	rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
	for entry in rt_string_directory.directory.entries:
		if str(entry.name) == "DCDATA":
			
			data_rva = entry.directory.entries[0].data.struct.OffsetToData
			size = entry.directory.entries[0].data.struct.Size
			data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
			config = v51_data(data, key)

		elif str(entry.name) in config.keys():

			data_rva = entry.directory.entries[0].data.struct.OffsetToData
			size = entry.directory.entries[0].data.struct.Size
			data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
			dec = rc4crypt(unhexlify(data), key)
			config[str(entry.name)] = filter(lambda x: x in string.printable, dec)
			config["Version"] = key[:-4]
	return config


def configClean(config):
	try:
		newConf = {}
		newConf["FireWallBypass"] = config["FWB"]
		newConf["FTPHost"] = config["FTPHOST"]
		newConf["FTPPassword"] = config["FTPPASS"]
		newConf["FTPPort"] = config["FTPPORT"]
		newConf["FTPRoot"] = config["FTPROOT"]
		newConf["FTPSize"] = config["FTPSIZE"]
		newConf["FTPKeyLogs"] = config["FTPUPLOADK"]
		newConf["FTPUserName"] = config["FTPUSER"]
		newConf["Gencode"] = config["GENCODE"]
		newConf["Mutex"] = config["MUTEX"]
		newConf["Domains"] = config["NETDATA"]
		newConf["OfflineKeylogger"] = config["OFFLINEK"]
		newConf["Password"] = config["PWD"]
		newConf["CampaignID"] = config["SID"]
		newConf["Version"] = config["Version"]
		return newConf
	except:
		return config
	
def run(data):
	versionKey = versionCheck(data)
	if versionKey != None:
		config = configExtract(data, versionKey)
		config = configClean(config)

		return config
	else:
		return None

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
				outFile.write("Key: {0}\t Value: {1}\n".format(key,value))
		
	else:
		print "[+] Printing Config to screen"
		for key, value in sorted(config.iteritems()):
			print "   [-] Key: {0}\t Value: {1}".format(key,value)
		print "[+] End of Config"
