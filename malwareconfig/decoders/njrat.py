from base64 import b64decode
from malwareconfig.common import Decoder


class njRat(Decoder):
    decoder_name = "njRat"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "njRAT"

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        string_list = self.file_info.dotnet_user_strings()

        config_dict = {}
        if '0.3.5' in string_list:
            version_index = string_list.index('0.3.5')
            config_dict["Campaign ID"] = b64decode(string_list[version_index-1])
            config_dict["version"] = string_list[version_index]
            config_dict["Install Name"] = string_list[version_index-4]
            config_dict["Install Dir"] = string_list[version_index-3]
            config_dict["Registry Value"] = string_list[version_index-2]
            config_dict["Domain"] = string_list[version_index+2]
            config_dict["Port"] = string_list[version_index+3]
            config_dict["Network Separator"] = string_list[version_index+3]
            config_dict["Install Flag"] = string_list[version_index+1]


        elif '0.3.6' in string_list:
            version_index = string_list.index('0.3.6')
            config_dict["Campaign ID"] = b64decode(string_list[version_index-1])
            config_dict["version"] = string_list[version_index]
            config_dict["Install Name"] = string_list[version_index-4]
            config_dict["Install Dir"] = string_list[version_index-3]
            config_dict["Registry Value"] = string_list[version_index-2]
            config_dict["Domain"] = string_list[version_index+2]
            config_dict["Port"] = string_list[version_index+3]
            config_dict["Network Separator"] = string_list[version_index+4]
            config_dict["Install Flag"] = string_list[version_index+5]

        elif '0.4.1a' in string_list:
            version_index = string_list.index('0.4.1a')
            config_dict["Campaign ID"] = b64decode(string_list[version_index-1])
            config_dict["version"] = string_list[version_index]
            config_dict["Install Name"] = string_list[version_index+2]
            config_dict["Install Dir"] = string_list[version_index+3]
            config_dict["Registry Value"] = string_list[version_index+4]
            config_dict["Domain"] = string_list[version_index+5]
            config_dict["Port"] = string_list[version_index+6]
            config_dict["Network Separator"] = string_list[version_index+7]
            config_dict["Install Flag"] = string_list[version_index+8]

        elif '0.5.0E' in string_list:
            version_index = string_list.index('0.5.0E')
            config_dict["Campaign ID"] = b64decode(string_list[version_index-1])
            config_dict["version"] = string_list[version_index]
            config_dict["Install Name"] = string_list[version_index+1]
            config_dict["Install Dir"] = string_list[version_index+2]
            config_dict["Registry Value"] = string_list[version_index+3]
            config_dict["Domain"] = string_list[version_index+4]
            config_dict["Port"] = string_list[version_index+5]
            config_dict["Network Separator"] = string_list[version_index+6]

        elif '0.6.4' in string_list:
            version_index = string_list.index('0.6.4')
            config_dict["Campaign ID"] = b64decode(string_list[version_index-1])
            config_dict["version"] = string_list[version_index]
            config_dict["Install Name"] = string_list[version_index+1]
            config_dict["Install Dir"] = string_list[version_index+2]
            config_dict["Registry Value"] = string_list[version_index+3]
            config_dict["Domain"] = string_list[version_index+4]
            config_dict["Port"] = string_list[version_index+5]
            config_dict["Network Separator"] = string_list[version_index+6]
            config_dict["Install Flag"] = string_list[version_index+7]

        elif '0.7.1' in string_list:
            version_index = string_list.index('0.7.1')
            config_dict["Campaign ID"] = b64decode(string_list[version_index-1])
            config_dict["version"] = string_list[version_index]
            config_dict["Install Name"] = string_list[version_index+2]
            config_dict["Install Dir"] = string_list[version_index+3]
            config_dict["Registry Value"] = string_list[version_index+4]
            config_dict["Domain"] = string_list[version_index+5]
            config_dict["Port"] = string_list[version_index+6]
            config_dict["Network Separator"] = string_list[version_index+7]
            config_dict["Install Flag"] = string_list[version_index+8]

        elif '0.7d' in string_list:
            version_index = string_list.index('0.7d')
            config_dict["Campaign ID"] = b64decode(string_list[version_index-1])
            config_dict["version"] = string_list[version_index]
            config_dict["Install Name"] = string_list[version_index+1]
            config_dict["Install Dir"] = string_list[version_index+2]
            config_dict["Registry Value"] = string_list[version_index+3]
            config_dict["Domain"] = string_list[version_index+4]
            config_dict["Port"] = string_list[version_index+5]
            config_dict["Network Separator"] = string_list[version_index+6]
            config_dict["Install Flag"] = string_list[version_index+7]

        elif'[endof]' in string_list:
            endof_index = string_list.index('[endof]')
            try:
                config_dict["Campaign ID"] = b64decode(string_list[endof_index-10])
            except:
                config_dict["Campaign ID"] = string_list[endof_index - 10]
            config_dict["version"] = string_list[endof_index-9]
            config_dict["Install Name"] = string_list[endof_index-7]
            config_dict["Install Dir"] = string_list[endof_index-6]
            config_dict["Registry Value"] = string_list[endof_index-5]
            config_dict["Domain"] = string_list[endof_index-4]
            config_dict["Port"] = string_list[endof_index-3]
            config_dict["Network Separator"] = string_list[endof_index-1]
            config_dict["Install Flag"] = string_list[endof_index-2]

        else:
            print("Unable to match a version")


        # Set the config to the class for use
        self.config = config_dict
