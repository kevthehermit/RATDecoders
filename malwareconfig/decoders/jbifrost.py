import javaobj # sudo pip3 install javaobj-py3
from xml.etree import ElementTree as ET
from malwareconfig import fileparser
from io import BytesIO
from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class Jbifrost(Decoder):
    decoder_name = "Jbifrost"
    decoder__version = 1
    decoder_author = ["@kevthehermit", "Chris"]
    decoder_description = "Jbifrost Java RAT"

    def __init__(self):
        self.config = {}


    @staticmethod
    def parse_xml(xml_string):
        # Convert to XML
        xml = ET.fromstring(xml_string)

        # Read the XML to a config dict
        properties_dict = {}

        for child in xml:
            if child.attrib:
                properties_dict[child.attrib['key']] = child.text

        return properties_dict

    @staticmethod
    def extract_rsa_key(java_serialized_data):
        deserialized_data = javaobj.loads(java_serialized_data)
        rsa_key_bytes = deserialized_data.encoded
        rsa_key_string = ''
        for b in rsa_key_bytes:
            # convert to unsigned int
            rsa_key_string += chr(b & 0xff)
        return rsa_key_string


    def extract_from_droppper(self):
        file_info = self.file_info

        try:
            # Read Files
            encrypted_aes_key = file_info.file_from_zip('mega.download')
            rsa_serialized_key = file_info.file_from_zip('sky.drive')
            aes_encrypted_config = file_info.file_from_zip('drop.box')

            # Deserailize and retrieve the RSA Key
            rsa_key_string = self.extract_rsa_key(rsa_serialized_key)

            # Decrypt the AES Key using the RSA Key
            aes_key = crypto.decrypt_rsa(rsa_key_string, encrypted_aes_key)

        except:
            # Read in serialized RSA KeyRep file.
            aes_encrypted_config = file_info.file_from_zip('lp/sq/d.png')
            aes_key = 'lks03oeldkfirowl'

        # Use the AES Key to decrpyt the config
        aes_decrypted_xml = crypto.decrypt_aes(aes_key[-16:], aes_encrypted_config)
        parsed_xml = self.parse_xml(aes_decrypted_xml)

        # Extract the implant using the xml properties
        rsa_serialized_key_path = parsed_xml['PRIVATE_PASSWORD'].lstrip('/')
        aes_path = parsed_xml['PASSWORD_CRYPTED'].lstrip('/')
        implant_path = parsed_xml['SERVER_PATH'].lstrip('/')

        rsa_serialized_key = file_info.file_from_zip(rsa_serialized_key_path)
        encrypted_aes_key = file_info.file_from_zip(aes_path)
        aes_encrypted_jar = file_info.file_from_zip(implant_path)

        # Another round of extraction
        rsa_key_string = Jbifrost.extract_rsa_key(rsa_serialized_key)
        aes_key = crypto.decrypt_rsa(rsa_key_string, encrypted_aes_key)

        implant_jar = crypto.decrypt_aes(aes_key[-16:], aes_encrypted_jar)

        # Update for new file
        new_info = fileparser.FileParser(rawdata=implant_jar)
        self.file_info = new_info

        # Run config again
        self.get_config()

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''


        file_info = self.file_info

        file_list = file_info.zip_namelist()

        # Look for Dropper
        if 'sky.drive' in file_list and 'mega.download' in file_list and 'drop.box' in file_list:
            self.extract_from_droppper()

        # Look for implant
        elif 'server/resources/config.json' in file_list and 'server/resources/Key1.json' in file_list and 'server/resources/Key2.json' in file_list:
            rsa_serialized_key = file_info.file_from_zip('server/resources/Key1.json')
            encrypted_aes_key = file_info.file_from_zip('server/resources/Key2.json')
            aes_encrypted_config = file_info.file_from_zip('server/resources/config.json')

            # Another round of extraction
            rsa_key_string = Jbifrost.extract_rsa_key(rsa_serialized_key)
            aes_key = crypto.decrypt_rsa(rsa_key_string, encrypted_aes_key)
            implant_config = crypto.decrypt_aes(aes_key[-16:], aes_encrypted_config)

            implant_config = implant_config.decode('utf-8').rstrip('\x0e')

            self.config = implant_config

        elif 'lp/sq/d.png' in file_info:
            self.extract_from_droppper()
        else:
            print
            '\n[+] Failed to find jBiFrost malware...'