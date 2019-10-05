from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class BlackNix(Decoder):
    decoder_name = "BlackNix"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "BlackNix RAT"

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''
        config_data = self.file_info.pe_resource_by_name("SETTINGS")

        # Decode String
        config_line = ''
        for c in config_data:
            config_line += chr(c-1)

        # Reverse the string
        config_line = config_line[::-1]

        # Get Fields
        fields = config_line.split('|')

        config_dict = {
                    'Mutex': fields[1],
                    'Anti Sandboxie': fields[2],
                    'Max Folder Size': fields[3],
                    'Delay Time': fields[4],
                    'Password': fields[5],
                    'Kernel Mode Unhooking': fields[6],
                    'User More Unhooking': fields[7],
                    'Melt Server': fields[8],
                    'Offline Screen Capture': fields[9],
                    'Offline Keylogger': fields[10],
                    'Copy To ADS': fields[11],
                    'Domain': fields[12],
                    'Persistence Thread': fields[13],
                    'Active X Key': fields[14],
                    'Registry Key': fields[15],
                    'Active X Run': fields[16],
                    'Registry Run': fields[17],
                    'Safe Mode Startup': fields[18],
                    'Inject winlogon.exe': fields[19],
                    'Install Name': fields[20],
                    'Install Path': fields[21],
                    'Campaign Name': fields[22],
                    'Campaign Group': fields[23]
                    }

        # Set the config to the class for use
        self.config = config_dict
