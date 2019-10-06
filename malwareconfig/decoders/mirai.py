import re
from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable

from binascii import hexlify, unhexlify

# temp imports
import re
import zlib
import uuid
from struct import unpack

class Mirai(Decoder):
    decoder_name = "Mirai"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Mirai decoder with varients"

    def __init__(self):
        self.config = {}

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''
        config_dict = {}

        file_data = self.file_info.file_data

        # Xor everything and look for some key words
        # 
        # Known keys
        #  0xDEADBEEF 0x22

        # Do we try to be clever or just bruteforce?

        regex_domain = re.compile(rb"(?!:\/\/)[a-zA-Z0-9-_]+\.*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}", re.IGNORECASE)
        regex_ip = re.compile(rb'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', re.IGNORECASE)


        match_words = [b'iptables', b'busybox', b'Mozilla']
        false_postive_c2 = [b'resolv.conf', b'schemas.xmlsoap.org', b'tftp.sh']
        c2_list = []

        for i in range(1,255):
            xor_data = crypto.decrypt_xor(bytes([i]), file_data)
            if any(word in xor_data for word in match_words):
                xor_key = i
                domain_results = re.findall(regex_domain, xor_data)
                ip_results = re.findall(regex_ip, xor_data)

                for c2 in domain_results:
                    # Sometimes some xor keys can be a bit annoying. 
                    if c2 not in false_postive_c2:
                        c2_list.append(c2.decode('utf-8'))
                for c2 in ip_results:
                    if c2 not in false_postive_c2:
                        c2_list.append(c2.decode('utf-8'))

        config_dict['Commment'] = "The C2 extraction uses a best effort xor decryption. There may be issues with some xor keys like 0x78"
        config_dict['C2'] = c2_list
        config_dict['xor'] = hex(xor_key)

        self.config = config_dict

        # no match
        # wicked, satori-v4, satori-v2, mirai-ssh, jenx

