from xml.etree import ElementTree as ET

from malwareconfig import crypto
from malwareconfig.common import Decoder


class AdWind(Decoder):
    decoder_name = "AdWind"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "AdWind Decoder"

    def __init__(self):
        self.config = {}

    @staticmethod
    def parse_config(old_config):
        if old_config['Version'] == 'Adwind RAT v1.0':
            new_config = {}
            new_config['Version'] = old_config['Version']
            new_config['Delay'] = old_config['delay']
            new_config['Domain'] = old_config['dns']
            new_config['Install Flag'] = old_config['instalar']
            new_config['Jar Name'] = old_config['jarname']
            new_config['Reg Key'] = old_config['keyClase']
            new_config['Install Folder'] = old_config['nombreCarpeta']
            new_config['Password'] = old_config['password']
            new_config['Campaign ID'] = old_config['prefijo']
            new_config['Port1'] = old_config['puerto1']
            new_config['Port2'] = old_config['puerto2']
            new_config['Reg Value'] = old_config['regname']
            return new_config

        if old_config['Version'] == 'Adwind RAT v2.0':
            new_config = {}
            new_config['Version'] = old_config['Version']
            new_config['Delay'] = old_config['delay']
            new_config['Domain'] = old_config['dns']
            new_config['Install Flag'] = old_config['instalar']
            new_config['Reg Key'] = old_config['keyClase']
            new_config['Password'] = old_config['password']
            new_config['Campaign ID'] = old_config['prefijo']
            new_config['Port1'] = old_config['puerto']
            return new_config
        return old_config

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        key = "awenubisskqi"

        # Get the file from the zip
        zip_xml = self.file_info.file_from_zip('config.xml')

        # No Easy way to detect version so just try it

        try:
            xml_string = crypto.decrypt_des_ecb(key[:-4], zip_xml)
        except ValueError:
            xml_string = crypto.decrypt_arc4(key, zip_xml)

        # Convert to XML
        xml = ET.fromstring(xml_string)

        # Read the XML to a config dict
        config_dict = {}

        for child in xml:
            if child.text.startswith("Adwind RAT"):
                config_dict['Version'] = child.text
            else:
                config_dict[child.attrib['key']] = child.text

        # Parse the config
        config_dict = self.parse_config(config_dict)

        # Set the config to the class for use
        self.config = config_dict
