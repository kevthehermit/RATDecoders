import sys
import binascii
import pefile
import struct
import hashlib
from Crypto.Cipher import AES
import xml.etree.ElementTree as ET

def derive_key(n_rounds,input_bf):
	intermediate = input_bf
	for i in range(0, n_rounds):
		sha = hashlib.sha256()
		sha.update(intermediate)
		current = sha.digest()
		intermediate += current
	return current

#expects a str of binary data open().read()
def trick_decrypt(data):
	key = derive_key(128, data[:32])
	iv = derive_key(128,data[16:48])[:16]
	aes = AES.new(key, AES.MODE_CBC, iv)
	mod = len(data[48:]) % 16
	if mod != 0:
		data += '0' * (16 - mod)
	return aes.decrypt(data[48:])[:-(16-mod)]

def get_rsrc(pe):
	ret = []
	for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
		if resource_type.name is not None:
			name = str(resource_type.name)
		else:
			name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
		if name == None:
			name = str(resource_type.struct.name)
		if hasattr(resource_type, 'directory'):
			for resource_id in resource_type.directory.entries:
				if hasattr(resource_id, 'directory'):
					for resource_lang in resource_id.directory.entries:
						data = pe.get_data(resource_lang.data.struct.OffsetToData,resource_lang.data.struct.Size)
						ret.append((name,data,resource_lang.data.struct.Size,resource_type))
	return ret

def decode_onboard_config(data):
	pe = pefile.PE(data=data)
	rsrcs = get_rsrc(pe)

	a = rsrcs[0][1]

	data = trick_decrypt(a[4:])
	length = struct.unpack_from('<I',data)[0]
	return data[8:length+8]

def config(data):
	xml = decode_onboard_config(data)
	root = ET.fromstring(xml)
	raw_config = {}
	for child in root:
		
		if hasattr(child, 'key'):
			tag = child.attrib["key"]
		else:
			tag = child.tag
		
		if tag == 'autorun':
			val = str(map(lambda x: x.items(), child.getchildren()))
		elif tag == 'servs':
			val = ','.join(map(lambda x: x.text, child.getchildren()))
		else:
			val = child.text

		raw_config[tag] = val

	return raw_config

