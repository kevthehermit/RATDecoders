from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class AAR(Decoder):
    decoder_name = "Template"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Base Template for Decoders"

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''


        file_data = self.file_info.file_data

        config_dict = {}

        # Set the config to the class for use
        self.config = config_dict
