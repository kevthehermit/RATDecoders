from xml.etree import ElementTree as ET

from malwareconfig.common import Decoder


class Adzok(Decoder):
    decoder_name = "Adzok"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Adzok Decoder"

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        # Get the file from the zip
        xml_string = self.file_info.file_from_zip('config.xml')

        # No Crypto just needs parsing

        # Convert to XML
        xml = ET.fromstring(xml_string)

        # Read the XML to a config dict
        config_dict = {}

        for child in xml:
            if child.attrib:
                if child.text and child.text.startswith("Adzok"):
                    config_dict['Version'] = child.text
                else:
                    # Remap the config keys to nicer names
                    config_map = {'dir': 'Install Path', 'reg': 'Registry Key', 'pass': 'Password', 'hidden': 'Hidden',
                                  'puerto': 'Port', 'ip': 'Domain', 'inicio': 'Install'}

                    config_dict[config_map[child.attrib['key']]] = child.text

        # Set the config to the class for use
        self.config = config_dict
