from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class Alina(Decoder):
    decoder_name = "Alina"
    decoder__version = 1
    decoder_author = ["@botnet_hunter, @kevthehermit"]
    decoder_description = "Point of sale malware designed to extract credit card information from RAM"
    hash_list = ['efd57cde8eee0aae832aac414e1b5577']

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''


        print(self.file_info.ascii_strings(min_len=4))

        config_dict = {}

        # Set the config to the class for use
        self.config = config_dict
