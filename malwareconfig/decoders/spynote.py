import re
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class SpyNote(Decoder):
    decoder_name = "SpyNote"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "SpyNote and MobiHook RAT Decoder"

    def __init__(self):
        self.config = {}


    @staticmethod
    def get_string(str_name, listoflists):
        for element in listoflists:
            if element[0] == str_name:
                return element[1]
        else:
            return None


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''
        config_dict = {}

        a,d,dx = self.file_info.parse_apk()

        arscobj = a.get_android_resources()

        # Force the analyze
        arscobj._analyse()

        package_name = arscobj.get_packages_names()[0]

        string_list = arscobj.values[package_name]['\x00\x00']['string']

        # Lets do a quick version check

        version_check5 = self.get_string('version', string_list)
        version_check6 = self.get_string('v', string_list)

        if version_check5:
            props = self.get_string('group_properties', string_list)
            config_dict['Hide Application'] = props[0]
            config_dict['WiFi Wakelock'] = props[1]
            config_dict['CPU Wakelock'] = props[2]
            config_dict['Root Permissions'] = props[3]
            config_dict['Device Admin'] = props[4]
            config_dict['Service Foreground'] = props[5]
            config_dict['Keylogger'] = props[6]
            config_dict['Repeating Alarm'] = props[7]

            config_dict['App Name'] = self.get_string('app_name', string_list)
            config_dict['Service Name'] = self.get_string('service_name', string_list)
            config_dict['host'] = self.get_string('host', string_list)
            config_dict['Victim Name'] = self.get_string('client_name', string_list)
            config_dict['Version'] = self.get_string('version', string_list)

        # this works for 6.4 and for mobihok as well. 
        if version_check6:
            props = self.get_string('gp', string_list)
            config_dict['Hide Application'] = props[0]
            config_dict['Keylogger'] = props[1]
            config_dict['Deactivate Icons'] = props[2]
            config_dict['Device Admin'] = props[3]
            config_dict['Root Permissions'] = props[4]

            config_dict['App Name'] = self.get_string('app_name', string_list)
            config_dict['Service Name'] = self.get_string('s', string_list)
            config_dict['port'] = self.get_string('p', string_list)
            config_dict['domain'] = self.get_string('h', string_list)
            config_dict['password'] = self.get_string('ps', string_list)
            config_dict['Victim Name'] = self.get_string('n', string_list)
            config_dict['Version'] = self.get_string('v', string_list)

        




        # Set the config to the class for use
        self.config = config_dict
