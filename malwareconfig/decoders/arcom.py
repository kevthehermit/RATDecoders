from base64 import b64decode

from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class Arcom(Decoder):
    decoder_name = "Arcom"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Arcom RAT Decoder"

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        key = "CVu3388fnek3W(3ij3fkp0930di"
        file_data = self.file_info.file_data

        coded_config = file_data.split(b"\x18\x12\x00\x00")[1][:-8]
        decoded_config = b64decode(coded_config)

        clear_config = crypto.decrypt_blowfish(key, decoded_config).decode('utf-8')

        config_dict = {}
        parts = clear_config.split('|')
        if len(parts) > 3:
            config_dict["Domain"] = parts[0]
            config_dict["Port"] = parts[1]
            config_dict["Install Path"] = parts[2]
            config_dict["Install Name"] = parts[3]
            config_dict["Startup Key"] = parts[4]
            config_dict["Campaign ID"] = parts[5]
            config_dict["Mutex Main"] = parts[6]
            config_dict["Mutex Per"] = parts[7]
            config_dict["YPER"] = parts[8]
            config_dict["YGRB"] = parts[9]
            config_dict["Mutex Grabber"] = parts[10]
            config_dict["Screen Rec Link"] = parts[11]
            config_dict["Mutex 4"] = parts[12]
            config_dict["YVID"] = parts[13]
            config_dict["YIM"] = parts[14]
            config_dict["NO"] = parts[15]
            config_dict["Smart Broadcast"] = parts[16]
            config_dict["YES"] = parts[17]
            config_dict["Plugins"] = parts[18]
            config_dict["Flag1"] = parts[19]
            config_dict["Flag2"] = parts[20]
            config_dict["Flag3"] = parts[21]
            config_dict["Flag4"] = parts[22]
            config_dict["WebPanel"] = parts[23]
            config_dict["Remote Delay"] = parts[24]

        # Set the config to the class for use
        self.config = config_dict
