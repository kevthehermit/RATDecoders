from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class Bozok(Decoder):
    decoder_name = "Bozok"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Bozok Decoder"

    def __init__(self):
        self.config = {}


    def get_config(self):
        """
        This is the main entry
        :return:
        """

        config_data = self.file_info.pe_resource_by_name('CFG')

        config_data = config_data.decode('utf-8').replace('\x00', '')
        config_fields = config_data.split('|')

        config_dict = {'ServerID': config_fields[0],
                       'InstallName': config_fields[2],
                       'StartupName': config_fields[3],
                       'Extension': config_fields[4],
                       'Password': config_fields[5],
                       'Install Flag': config_fields[6],
                       'Startup Flag': config_fields[7],
                       'Visible Flag': config_fields[8],
                       'Unknown Flag1': config_fields[9],
                       'Unknown Flag2': config_fields[10],
                       'Port': config_fields[11],
                       'Domain': config_fields[12],
                       'Unknown Flag3': config_fields[13]
                       }

        # Set the config to the class for use
        self.config = config_dict
