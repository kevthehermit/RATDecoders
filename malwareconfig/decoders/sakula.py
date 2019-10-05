import re
from struct import unpack
from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class Sakula(Decoder):
    decoder_name = "Sakula"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Sakula Rat"

    def __init__(self):
        self.config = {}

    @staticmethod
    def config_v1(config_list):
        print("Found Version < 1.3")
        config_dict = {}
        counter = 1
        for config in config_list:
            config_dict['Domain'] = config[0].rstrip(b'\x88')
            config_dict['URI GET1 Folder'] = config[1].rstrip(b'\x88')
            config_dict['URI GET3 File'] = config[2].rstrip(b'\x88')
            config_dict['URI GET2 File'] = config[3].rstrip(b'\x88')
            config_dict['URI GET3 Arg'] = config[4].rstrip(b'\x88')
            config_dict['Copy File Name'] = config[5].rstrip(b'\x88')
            config_dict['Service Name'] = config[6].rstrip(b'\x88')
            config_dict['Service Description'] = config[7].rstrip(b'\x88')
            config_dict['Waiting Time'] = unpack('>H', config[8][:2].rstrip(b'\x88'))[0]
            counter += 1
        return config_dict

    @staticmethod
    def config_v2(config_list):
        print("Found Version > 1.2")
        config_dict = {}
        counter = 1
        for config in config_list:
            config_dict['{}_Domain'.format(counter)] = config[0].rstrip(b'V')
            config_dict['{}_URI GET1 Folder'.format(counter)] = config[1].rstrip(b'V')
            config_dict['{}_URI GET3 File'.format(counter)] = config[2].rstrip(b'V')
            config_dict['{}_URI GET2 File'.format(counter)] = config[3].rstrip(b'V')
            config_dict['{}_URI GET3 Arg'.format(counter)] = config[4].rstrip(b'V')
            config_dict['{}_Copy File Name'.format(counter)] = config[5].rstrip(b'V')
            config_dict['{}_AutoRun Key'.format(counter)] = config[6].rstrip(b'V')
            config_dict['{}_Copy File Path'.format(counter)] = config[7].rstrip(b'V')
            config_dict['{}_Campaign ID'.format(counter)] = config[8].rstrip(b'V')
            config_dict['{}_Waiting Time'.format(counter)] = unpack('<H', config[9][:2].rstrip(b'V'))[0]
            counter += 1
        return config_dict


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        config_dict = {}

        file_data = self.file_info.file_data

        # RE for 1.0 and 1.1
        re_pattern1 = b'([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})(.{12}\x77\x77\x77\x77)'
        # RE for 1.2, 1.3, 1.4
        re_pattern2 = b'([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{12})(0uVVVVVV)'

        xor_data = crypto.decrypt_xor('\x88', file_data)

        config_list = re.findall(re_pattern1, xor_data)

        for c in config_list:
            if any(b".exe" in s for s in c):
                config_dict = Sakula.config_v1(config_list)

        # XOR for later versions

        xor_data = crypto.decrypt_xor('V', file_data)

        config_list = re.findall(re_pattern2, xor_data)


        for c in config_list:
            if any(b".exe" in s for s in c):
                config_dict = Sakula.config_v2(config_list)


        # Set the config to the class for use
        self.config = config_dict
