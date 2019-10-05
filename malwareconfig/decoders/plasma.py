import re
import binascii
import hashlib

from base64 import b64decode

from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable

# temp imports
import re
import zlib
import uuid
from struct import unpack

class Plasma(Decoder):
    decoder_name = "Plasma"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Plasma decoder for 1.7 This is identical to LuminosityLink"

    def __init__(self):
        self.config = {}

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        config_dict = {}

        # Getting resource is tough so instead we grab the base64 string from the raw
        file_data = self.file_info.file_data
        re_pattern = b'[a-zA-Z0-9+/]{60,}={0,2}'
        conf_string = re.findall(re_pattern, file_data)[0]

        password = "IUWEEQWIOER$89^*(&@^$*&#@$HAFKJHDAKJSFHjd89379327AJHFD*&#($hajklshdf##*$&^(AAA"

        # b64decode
        conf_string = b64decode(conf_string)

        

        # Derive Key
        key_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
        aes_key = key_hash[:30] + key_hash + '00'

        # Decrypt
        decrypted = crypto.decrypt_aes(binascii.unhexlify(aes_key), conf_string)

        string_list = decrypted.decode('utf-8').split('*')

        config_dict = {}
        config_dict["Domain"] = string_list[1]
        config_dict["Port"] = string_list[2]
        config_dict["Password"] = string_list[3]
        config_dict["Install Name"] = string_list[4]
        config_dict["Startup Name"] = string_list[5]
        config_dict["Campaign ID"] = string_list[6]
        config_dict["Backup Domain"] = string_list[7]


        self.config = config_dict