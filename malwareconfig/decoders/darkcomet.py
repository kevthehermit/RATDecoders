from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class DarkComet(Decoder):
    decoder_name = "DarkComet"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "DarkComet decoder for all known versions"

    def __init__(self):
        self.config = {}

    @staticmethod
    def get_version(raw_data):
        if b'#KCMDDC2#' in raw_data:
            return '#KCMDDC2#-890'
        elif b'#KCMDDC4#' in raw_data:
            return '#KCMDDC4#-890'
        elif b'#KCMDDC42#' in raw_data:
            return '#KCMDDC42#-890'
        elif b'#KCMDDC42F#' in raw_data:
            return '#KCMDDC42F#-890'
        elif b'#KCMDDC5#' in raw_data:
            return '#KCMDDC5#-890'
        elif b'#KCMDDC51#' in raw_data:
            return '#KCMDDC51#-890'
        else:
            return None

    @staticmethod
    def parse_v5(file_info, dc_version):
        config = {}

        # Get the config section
        config_data = file_info.pe_resource_by_name("DCDATA")

        # Decrypt the config using the key
        crypted_config = bytes.fromhex(config_data.decode())
        clear_config = crypto.decrypt_arc4(dc_version, crypted_config)

        # Parse the config entries to get a json object
        config_list = clear_config.split(b'\r\n')
        for entries in config_list[1:-1]:
            key, value = entries.split(b'=')
            key = key.strip().decode('utf-8')
            value = value.rstrip()[1:-1]
            clean_value = string_printable(value.decode('utf-8'))
            config[key] = clean_value
        config['Version'] = dc_version

        # return the json
        return config

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        file_data = self.file_info.file_data

        # Version Check
        dc_version = self.get_version(file_data)

        # The version dictates how the resources are saved in the binary

        if '5' in dc_version:
            raw_config = self.parse_v5(self.file_info, dc_version)

        self.config = raw_config
