import binascii
from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class BlueBanana(Decoder):
    decoder_name = "BlueBanana"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Decoder for Blue Banana"

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''
        key1 = '15af8sd4s1c5s511'
        key2 = '4e3f5a4c592b243f'

        crypted_config = self.file_info.file_from_zip('config.txt')

        first_round = crypto.decrypt_aes(key1, binascii.unhexlify(crypted_config))
        clear_config = crypto.decrypt_aes(key2, binascii.unhexlify(first_round[:-16]))

        fields = clear_config.decode('utf-8').split("<separator>")

        config_dict = {'Domain': fields[0],
                       'Password': fields[1],
                       'Port1': fields[2],
                       'Port2': fields[3]
                       }
        if len(fields) > 4:
            config_dict['InstallName'] = fields[4]
            config_dict['JarName'] = fields[5]

        # Set the config to the class for use
        self.config = config_dict
