import re
import binascii
import hashlib

from base64 import b64decode

from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class AAR(Decoder):
    decoder_name = "AAR"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Albertino Advanced RAT decoder"

    def __init__(self):
        self.config = {}

    def parse_config(self, clean_config):
        sections = clean_config.split('*')
        config_dict = {}
        if len(sections) == 7:
            config_dict['Version'] = '4.x'
            config_dict['Domain1'] = sections[0]
            config_dict['Domain2'] = sections[1]
            config_dict['RegKey1'] = sections[2]
            config_dict['RegKey2'] = sections[3]
            config_dict['Port1'] = sections[4]
            config_dict['Port2'] = sections[5]
            config_dict['Mutex'] = sections[6]
        if len(sections) == 5:
            config_dict['Version'] = '2.x'
            config_dict['Domain1'] = sections[0]
            config_dict['Domain2'] = sections[1]
            config_dict['Port1'] = sections[2]
            config_dict['Port2'] = sections[3]
            config_dict['AntiDebug'] = sections[4]
        return config_dict

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        # Known Values
        key = '&%#@?,:*'
        iv = b'\x12\x34\x56\x78\x90\xab\xcd\xef'

        file_data = self.file_info.file_data

        # Get the base64 config
        search = re.search(b'\x01\x96\x01(.*)@@', file_data)
        coded_config = search.group(0).replace(b'@', b'')[3:]

        # decode the config
        decoded_config = b64decode(coded_config)

        # Decrypt
        clear_config = crypto.decrypt_des_cbc(key, decoded_config, iv=iv)

        # Parse the config
        config_dict = self.parse_config(clear_config.decode('utf-8'))

        # Set the config to the class for use
        self.config = config_dict
