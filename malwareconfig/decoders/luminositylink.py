import re
import binascii
import hashlib

from base64 import b64decode

from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class LuminosityLink(Decoder):
    decoder_name = "LuminosityLink"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "LuminosityLink decoder"

    def __init__(self):
        self.config = {}

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        # Getting resource is tough so instead we grab the base64 string from the raw
        file_data = self.file_info.file_data
        re_pattern = b'[a-zA-Z0-9+/]{60,}={0,2}'
        conf_string = re.findall(re_pattern, file_data)[0]
        # b64decode
        conf_string = b64decode(conf_string)

        # Derive Key
        key_hash = hashlib.md5('Specify a Password'.encode('utf-8')).hexdigest()
        aes_key = key_hash[:30] + key_hash + '00'

        # Decrypt
        decrypted = crypto.decrypt_aes(binascii.unhexlify(aes_key), conf_string)

        string_list = decrypted.decode('utf-8').split('|')

        config_dict = {}
        config_dict["Domain"] = string_list[0]
        config_dict["Port"] = string_list[1]
        config_dict["BackUp Domain"] = string_list[2]
        config_dict["Install Name"] = string_list[3]
        config_dict["Startup Name"] = string_list[4]
        config_dict["Campaign ID"] = string_list[5]

        # Set the config to the class for use
        self.config = config_dict
