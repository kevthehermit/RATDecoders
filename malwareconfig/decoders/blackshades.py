import re
import binascii

from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable

prng_seed = 0

class BlackShades(Decoder):
    decoder_name = "BlackShades"
    decoder__version = 1
    decoder_author = "@botnet_hunter, @kevthehermit"
    decoder_description = "BlackShades Decoder"

    def __init__(self):
        self.config = {}

    @staticmethod
    def is_valid_config(config):
        if config[:3] != "\x0c\x0c\x0c":
            return False
        if config.count("\x0C\x0C\x0C") < 15:
            return False
        return True

    @staticmethod
    def get_next_rng_value():
        global prng_seed
        prng_seed = ((prng_seed * 1140671485 + 12820163) & 0xffffff)
        return int(prng_seed / 65536)

    @staticmethod
    def decrypt_configuration(hex):
        global prng_seed

        hex = hex.decode('utf-8')
        ascii = binascii.unhexlify(hex)
        tail = ascii[0x20:]

        pre_check = []
        for x in range(3):
            pre_check.append(tail[x] ^ 0x0c)

        for x in range(0xffffff):
            prng_seed = x
            if BlackShades.get_next_rng_value() != pre_check[0] or BlackShades.get_next_rng_value() != pre_check[1] or BlackShades.get_next_rng_value() != pre_check[2]:
                continue
            prng_seed = x

            config_bytes = []

            for c in tail:
                config_bytes.append(chr(c ^ int(BlackShades.get_next_rng_value())))

            config = "".join(config_bytes)

            if BlackShades.is_valid_config(config):
                return config.split("\x0c\x0c\x0c")
        return None

    def extract_config(self):
        file_data = self.file_info.file_data
        config_pattern = re.findall(b'[0-9a-fA-F]{154,}', file_data)
        for s in config_pattern:
            if (len(s) % 2) == 1:
                s = s[:-1]
            return s

    @staticmethod
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

    def get_config(self):
        """
        This is the main entry
        :return:
        """

        # Extract Config
        config_data = self.extract_config()

        # Decrypt The Config
        clear_config = self.decrypt_configuration(config_data)

        # Parse Config
        config_dict = BlackShades.config_parser(clear_config)

        # Set the config to the class for use
        self.config = config_dict
