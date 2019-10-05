from base64 import b64decode
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class ClientMesh(Decoder):
    decoder_name = "ClientMesh"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "ClientMesh Decoder"

    def __init__(self):
        self.config = {}

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        file_data = self.file_info.file_data
        splits = file_data.split(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7e')

        config_data = b64decode(splits[-1]).decode('utf-8')

        fields = config_data.split('``')

        config_dict = {
            'Domain': fields[0],
            'Port': fields[1],
            'Password': fields[2],
            'CampaignID': fields[3],
            'MsgBoxFlag': fields[4],
            'MsgBoxTitle': fields[5],
            'MsgBoxText': fields[6],
            'Startup': fields[7],
            'RegistryKey': fields[8],
            'RegistryPersistance': fields[9],
            'LocalKeyLogger': fields[10],
            'VisibleFlag': fields[11],
            'Unknown': fields[12]
        }

        # Set the config to the class for use
        self.config = config_dict
