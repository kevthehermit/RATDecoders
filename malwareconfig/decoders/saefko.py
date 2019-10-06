import re
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class Saefko(Decoder):
    decoder_name = "Saefko"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Saefko RAT Decoder"

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''
        config_dict = {}

        #Initial settings are appended to the end of the file
        file_data = self.file_info.file_data

        config_search = re.search(b'-START-(.*)-END-', file_data)
        if config_search:
            config_string = config_search.group(1).decode('utf-8')
            config_list = config_string.split('|')

            config_dict['server_url'] = config_list[0]
            config_dict['server_pass'] = config_list[1]
            config_dict['refresh_rate'] = config_list[2]
            config_dict['require_admin'] = config_list[3]
            config_dict['usbinfection'] = config_list[4]
            config_dict['startup_install'] = config_list[5]
            config_dict['require_online_resources'] = config_list[6]
            config_dict['ApplicationMutex'] = config_list[7]
            config_dict['ClipBoardLogging'] = config_list[8]


        # Set the config to the class for use
        self.config = config_dict
