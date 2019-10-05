from malwareconfig.crypto import decrypt_arc4
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable

from binascii import hexlify
import re


class Remcos(Decoder):
    decoder_name = "Remcos"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Remcos Decoder"

    def __init__(self):
        self.config = {}



    def get_config(self):
        '''
        This is the main entry
        :return:
        '''
        # Use file data to get version number

        version_string = "Unknown"
        ascii_strings = self.file_info.ascii_strings()
        for s in ascii_strings:
            if re.search(b'^[12]\.\d+\d{0,1}.*[FPL].*', s):
                version_string = s
            
        res_data = self.file_info.pe_resource_by_name("SETTINGS")
        key_length_byte = res_data[0]
        key_length = key_length_byte
        key = res_data[1:key_length+1]
        encrypted_config = res_data[key_length+1:]
        decrypted_config = decrypt_arc4(key, encrypted_config)

        config_string = decrypted_config.decode('utf-8')

        # Parse the config

        if '@@' in config_string:
            config_list = config_string.split("@@")

        else:
            config_list = config_string.split('\x1e')

        domain_string = config_list[0].split("|")
        domain_list = []
        for domain in domain_string:
            parts = domain.split(":")
            if len(parts) == 3:
                dom = {
                    "c2:": parts[0],
                    "port": parts[1],
                    "password": parts[2]
                }
                domain_list.append(dom)

        raw_config = {
            "version": version_string.decode('utf-8'),
            "domains": domain_list,
            "mutex": config_list[14],
            "Campaign": config_list[1],
            "Connection Interval": config_list[2],
            "Connection Delay": ord(config_list[3]),
            "screenshot Windows": config_list[23],
            "Keylog file": config_list[17].replace("\x00", ""),
            "Install Name": config_list[10].replace("\x00", "")
        }

        self.config = raw_config
