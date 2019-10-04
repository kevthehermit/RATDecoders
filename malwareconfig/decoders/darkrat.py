from base64 import b64decode

from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class DarkRAT(Decoder):
    decoder_name = "DarkRAT"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "darkrat RAT Decoder"

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        file_data = self.file_info.file_data
        config_dict = {}
        raw_config = file_data.split(b'@1906dark1996coder@')
        if len(raw_config) > 3:
            config_dict['Domain'] = raw_config[1][7:-1]
            config_dict['AutoRun'] = raw_config[2]
            config_dict['USB Spread'] = raw_config[3]
            config_dict['Hide Form'] = raw_config[4]
            config_dict['Msg Box Title'] = raw_config[6]
            config_dict['Msg Box Text'] = raw_config[7]
            config_dict['Timer Interval'] = raw_config[8]
            if raw_config[5] == 4:
                config_dict['Msg Box Type'] = 'Information'
            elif raw_config[5] == 2:
                config_dict['Msg Box Type'] = 'Question'
            elif raw_config[5] == 3:
                config_dict['Msg Box Type'] = 'Exclamation'
            elif raw_config[5] == 1:
                config_dict['Msg Box Type'] = 'Critical'
            else:
                config_dict['Msg Box Type'] = 'None'

        # Set the config to the class for use
        self.config = config_dict
