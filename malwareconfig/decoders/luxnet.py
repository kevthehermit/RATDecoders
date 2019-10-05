from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class LuxNet(Decoder):
    decoder_name = "LuxNet"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Luxnet RAT Decoder"

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''
        config_dict = {}

        user_strings = self.file_info.dotnet_user_strings()
        base_location = user_strings.index("SocketException")
        config_dict['domain'] = user_strings[base_location-2]
        config_dict['port'] = user_strings[base_location-1]


        # Set the config to the class for use
        self.config = config_dict
