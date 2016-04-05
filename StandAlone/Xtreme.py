#!/usr/bin/env python
'''
xtreme Rat Config Decoder
'''


__description__ = 'xtreme Rat Config Extractor'
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
try:
	import pefile
except ImportError:
	print "Couldn't Import pefile. Try 'sudo pip install pefile'"



# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''

def run(data):
	key = "C\x00O\x00N\x00F\x00I\x00G"
	codedConfig = configExtract(data)
	if codedConfig is not None:
        	rawConfig = rc4crypt(codedConfig, key)
        	#1.3.x # Not implemented yet
        	if len(rawConfig) == 0xe10:
        		config = None
        	#2.9.x #Not a stable extract
        	elif len(rawConfig) == 0x1390 or len(rawConfig) == 0x1392:
        		config = v29(rawConfig)
        	#3.1 & 3.2
        	elif len(rawConfig) == 0x5Cc:
        		config = v32(rawConfig)
        	#3.5
        	elif len(rawConfig) == 0x7f0:
        		config = v35(rawConfig)
        	else:
        		config = None
        	return config
        else:
                print '[-] Coded config not found'
                sys.exit()
	
		
#Helper Functions Go Here
def rc4crypt(data, key): # modified for bad implemented key length
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % 6])) % 256
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
			if str(entry.name) == "XTREME":
				data_rva = entry.directory.entries[0].data.struct.OffsetToData
				size = entry.directory.entries[0].data.struct.Size
				data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
				return data
	except:
		return None	

		
def v29(rawConfig):
	dict = {}
	dict["ID"] = getUnicodeString(rawConfig, 0x9e0)
	dict["Group"] = getUnicodeString(rawConfig, 0xa5a)
	dict["Version"] = getUnicodeString(rawConfig, 0xf2e) # use this to recalc offsets
	dict["Mutex"] = getUnicodeString(rawConfig, 0xfaa)
	dict["Install Dir"] = getUnicodeString(rawConfig, 0xb50)
	dict["Install Name"] = getUnicodeString(rawConfig, 0xad6)
	dict["HKLM"] = getUnicodeString(rawConfig, 0xc4f)
	dict["HKCU"] = getUnicodeString(rawConfig, 0xcc8)
	dict["Custom Reg Key"] = getUnicodeString(rawConfig, 0xdc0)
	dict["Custom Reg Name"] = getUnicodeString(rawConfig, 0xe3a)
	dict["Custom Reg Value"] = getUnicodeString(rawConfig, 0xa82)
	dict["ActiveX Key"] = getUnicodeString(rawConfig, 0xd42)
	dict["Injection"] = getUnicodeString(rawConfig, 0xbd2)
	dict["FTP Server"] = getUnicodeString(rawConfig, 0x111c)
	dict["FTP UserName"] = getUnicodeString(rawConfig, 0x1210)
	dict["FTP Password"] = getUnicodeString(rawConfig, 0x128a)
	dict["FTP Folder"] = getUnicodeString(rawConfig, 0x1196)
	dict["Domain1"] = str(getUnicodeString(rawConfig, 0x50)+":"+str(unpack("<I",rawConfig[0:4])[0]))
	dict["Domain2"] = str(getUnicodeString(rawConfig, 0xca)+":"+str(unpack("<I",rawConfig[4:8])[0]))
	dict["Domain3"] = str(getUnicodeString(rawConfig, 0x144)+":"+str(unpack("<I",rawConfig[8:12])[0]))
	dict["Domain4"] = str(getUnicodeString(rawConfig, 0x1be)+":"+str(unpack("<I",rawConfig[12:16])[0]))
	dict["Domain5"] = str(getUnicodeString(rawConfig, 0x238)+":"+str(unpack("<I",rawConfig[16:20])[0]))
	dict["Domain6"] = str(getUnicodeString(rawConfig, 0x2b2)+":"+str(unpack("<I",rawConfig[20:24])[0]))
	dict["Domain7"] = str(getUnicodeString(rawConfig, 0x32c)+":"+str(unpack("<I",rawConfig[24:28])[0]))
	dict["Domain8"] = str(getUnicodeString(rawConfig, 0x3a6)+":"+str(unpack("<I",rawConfig[28:32])[0]))
	dict["Domain9"] = str(getUnicodeString(rawConfig, 0x420)+":"+str(unpack("<I",rawConfig[32:36])[0]))
	dict["Domain10"] = str(getUnicodeString(rawConfig, 0x49a)+":"+str(unpack("<I",rawConfig[36:40])[0]))
	dict["Domain11"] = str(getUnicodeString(rawConfig, 0x514)+":"+str(unpack("<I",rawConfig[40:44])[0]))
	dict["Domain12"] = str(getUnicodeString(rawConfig, 0x58e)+":"+str(unpack("<I",rawConfig[44:48])[0]))
	dict["Domain13"] = str(getUnicodeString(rawConfig, 0x608)+":"+str(unpack("<I",rawConfig[48:52])[0]))
	dict["Domain14"] = str(getUnicodeString(rawConfig, 0x682)+":"+str(unpack("<I",rawConfig[52:56])[0]))
	dict["Domain15"] = str(getUnicodeString(rawConfig, 0x6fc)+":"+str(unpack("<I",rawConfig[56:60])[0]))
	dict["Domain16"] = str(getUnicodeString(rawConfig, 0x776)+":"+str(unpack("<I",rawConfig[60:64])[0]))
	dict["Domain17"] = str(getUnicodeString(rawConfig, 0x7f0)+":"+str(unpack("<I",rawConfig[64:68])[0]))
	dict["Domain18"] = str(getUnicodeString(rawConfig, 0x86a)+":"+str(unpack("<I",rawConfig[68:72])[0]))
	dict["Domain19"] = str(getUnicodeString(rawConfig, 0x8e4)+":"+str(unpack("<I",rawConfig[72:76])[0]))
	dict["Domain20"] = str(getUnicodeString(rawConfig, 0x95e)+":"+str(unpack("<I",rawConfig[76:80])[0]))

	return dict
		
def v32(rawConfig):
	dict = {}
	dict["ID"] = getUnicodeString(rawConfig, 0x1b4)
	dict["Group"] = getUnicodeString(rawConfig, 0x1ca)
	dict["Version"] = getUnicodeString(rawConfig, 0x2bc)
	dict["Mutex"] = getUnicodeString(rawConfig, 0x2d4)
	dict["Install Dir"] = getUnicodeString(rawConfig, 0x1f8)
	dict["Install Name"] = getUnicodeString(rawConfig, 0x1e2)
	dict["HKLM"] = getUnicodeString(rawConfig, 0x23a)
	dict["HKCU"] = getUnicodeString(rawConfig, 0x250)
	dict["ActiveX Key"] = getUnicodeString(rawConfig, 0x266)
	dict["Injection"] = getUnicodeString(rawConfig, 0x216)
	dict["FTP Server"] = getUnicodeString(rawConfig, 0x35e)
	dict["FTP UserName"] = getUnicodeString(rawConfig, 0x402)
	dict["FTP Password"] = getUnicodeString(rawConfig, 0x454)
	dict["FTP Folder"] = getUnicodeString(rawConfig, 0x3b0)
	dict["Domain1"] = str(getUnicodeString(rawConfig, 0x14)+":"+str(unpack("<I",rawConfig[0:4])[0]))
	dict["Domain2"] = str(getUnicodeString(rawConfig, 0x66)+":"+str(unpack("<I",rawConfig[4:8])[0]))
	dict["Domain3"] = str(getUnicodeString(rawConfig, 0xb8)+":"+str(unpack("<I",rawConfig[8:12])[0]))
	dict["Domain4"] = str(getUnicodeString(rawConfig, 0x10a)+":"+str(unpack("<I",rawConfig[12:16])[0]))
	dict["Domain5"] = str(getUnicodeString(rawConfig, 0x15c)+":"+str(unpack("<I",rawConfig[16:20])[0]))
	dict["Msg Box Title"] = getUnicodeString(rawConfig, 0x50c)
	dict["Msg Box Text"] = getUnicodeString(rawConfig, 0x522)
	return dict
		

def v35(rawConfig):
	dict = {}
	dict["ID"] = getUnicodeString(rawConfig, 0x1b4)
	dict["Group"] = getUnicodeString(rawConfig, 0x1ca)
	dict["Version"] = getUnicodeString(rawConfig, 0x2d8)
	dict["Mutex"] = getUnicodeString(rawConfig, 0x2f0)
	dict["Install Dir"] = getUnicodeString(rawConfig, 0x1f8)
	dict["Install Name"] = getUnicodeString(rawConfig, 0x1e2)
	dict["HKLM"] = getUnicodeString(rawConfig, 0x23a)
	dict["HKCU"] = getUnicodeString(rawConfig, 0x250)
	dict["ActiveX Key"] = getUnicodeString(rawConfig, 0x266)
	dict["Injection"] = getUnicodeString(rawConfig, 0x216)
	dict["FTP Server"] = getUnicodeString(rawConfig, 0x380)
	dict["FTP UserName"] = getUnicodeString(rawConfig, 0x422)
	dict["FTP Password"] = getUnicodeString(rawConfig, 0x476)
	dict["FTP Folder"] = getUnicodeString(rawConfig, 0x3d2)
	dict["Domain1"] = str(getUnicodeString(rawConfig, 0x14)+":"+str(unpack("<I",rawConfig[0:4])[0]))
	dict["Domain2"] = str(getUnicodeString(rawConfig, 0x66)+":"+str(unpack("<I",rawConfig[4:8])[0]))
	dict["Domain3"] = str(getUnicodeString(rawConfig, 0xb8)+":"+str(unpack("<I",rawConfig[8:12])[0]))
	dict["Domain4"] = str(getUnicodeString(rawConfig, 0x10a)+":"+str(unpack("<I",rawConfig[12:16])[0]))
	dict["Domain5"] = str(getUnicodeString(rawConfig, 0x15c)+":"+str(unpack("<I",rawConfig[16:20])[0]))
	dict["Msg Box Title"] = getUnicodeString(rawConfig, 0x52c)
	dict["Msg Box Text"] = getUnicodeString(rawConfig, 0x542)
	return dict


def getString(buf,pos):
	out = ""
	for c in buf[pos:]:
		if ord(c) == 0:
			break
		out += c
	
	if out == "":
		return None
	else:
		return out

def getUnicodeString(buf,pos):
	out = ""
	for i in range(len(buf[pos:])):
		if not (ord(buf[pos+i]) >= 32 and ord(buf[pos+i]) <= 126) and not (ord(buf[pos+i+1]) >= 32 and ord(buf[pos+i+1]) <= 126):
			out += "\x00"
			break
		out += buf[pos+i]
	if out == "":
		return None
	else:
		return out.replace("\x00","")


#Recursive Function Goes Here


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
		print "[+] Sorry No Recursive Yet Check Back Soon"
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
