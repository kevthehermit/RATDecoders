import re
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class Hrat(Decoder):
    decoder_name = "Hrat"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Houdini and WSH RAT Decoder"

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

        # Lets try to decode some common types
        # 


        host_search = re.search(b'host = "(.*)"', file_data)
        port_search = re.search(b'port = ([0-9]{1,5})', file_data)
        install_search = re.search(b'installdir = "(.*)"', file_data)
        runasadmin_search = re.search(b'runAsAdmin = (true|false)', file_data)
        lnkfile_search = re.search(b'lnkfile = (true|false)', file_data)
        lnkfolder_search = re.search(b'lnkfolder = (true|false)', file_data)

        config_dict["host"] = host_search.group(1).decode('utf-8')
        config_dict["port"] = port_search.group(1).decode('utf-8')
        config_dict["Install Dir"] = install_search.group(1).decode('utf-8')
        config_dict["Run as admin"] = runasadmin_search.group(1).decode('utf-8')
        config_dict["lnk_file"] = lnkfile_search.group(1).decode('utf-8')
        config_dict['lnk_dir'] = lnkfolder_search.group(1).decode('utf-8')

        # Set the config to the class for use
        self.config = config_dict
