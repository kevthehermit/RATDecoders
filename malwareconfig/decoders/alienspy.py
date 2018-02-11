import re
import json
from zipfile import ZipFile
from io import BytesIO

from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class AlienSpy(Decoder):
    decoder_name = "AlienSpy"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "AlienSpy for several Versions"

    def __init__(self):
        self.config = {}

    @staticmethod
    def version_a(enckey, coded_jar):
        config_dict = {}
        for key in enckey:
            decoded_data = crypto.decrypt_arc4(key, coded_jar)
            try:
                decoded_jar = ZipFile(BytesIO(decoded_data))
                raw_config = decoded_jar.read('org/jsocket/resources/config.json')
                config = json.loads(raw_config)
                for k, v in config.iteritems():
                    config_dict[k] = v
                config_dict['ConfigKey'] = key
                return config_dict
            except:
                pass


    @staticmethod
    def version_b(enckey, coded_jar):
        config_dict = {}
        for key in enckey:
            decoded_data = crypto.decrypt_arc4(key, coded_jar)

            decoded_jar = ZipFile(BytesIO(decoded_data))
            raw_config = decoded_jar.read('config.xml').decode('utf-8')

            for line in raw_config.split('\n'):
                if line.startswith('<entry key'):
                    config_dict[re.findall('key="(.*?)"', line)[0]] = re.findall('>(.*?)</entry', line)[0]
            config_dict['ConfigKey'] = key
            return config_dict

    @staticmethod
    def version_c(enckey, coded_jar, rounds=20, P=0xB7E15163, Q=0x9E3779B9):
        config_dict = {}
        for key in enckey:
            decoded_data = crypto.decrypt_RC6(key, coded_jar, rounds=rounds, P=P, Q=Q)
            try:
                decoded_jar = ZipFile(BytesIO(decoded_data))
                raw_config = decoded_jar.read('org/jsocket/resources/config.json')
                raw_config = raw_config.decode('utf-8')
                config = json.loads(raw_config)
                for k, v in config.items():
                    config_dict[k] = v
                config_dict['ConfigKey'] = key
                return config_dict
            except Exception as e:
                print(e)
                pass

    @staticmethod
    def version_d(enckey, coded_jar):
        return AlienSpy.version_c(enckey, coded_jar, rounds=22, P=0xb7e15263, Q=0x9e3779c9)

    @staticmethod
    def decrypt_XOR(keys, data):
        for key in keys:
            res = ""
            for i in range(len(data)):
                res += chr(ord(data[i]) ^ ord(key[i % len(key)]))
            if "SERVER" in res:
                return res

    @staticmethod
    def xor_config(data):
        config_dict = {}
        xor_keys = ["0x999sisosouuqjqhyysuhahyujssddqsad23rhggdsfsdfs",
                    "VY999sisosouuqjqhyysuhahyujssddqsad22rhggdsfsdfs",
                    "ABJSIOODKKDIOSKKJDJUIOIKASJIOOQKSJIUDIKDKIAS",
                    "fkfjgioelsqisoosidiijsdndcbhchyduwiqoqpqwoieweueidjdshsjahshquuiqoaooasisjdhdfh",
                    "adsdcwegtryhyurtgwefwedwscsdcwsdfcasfwqedfwefsdfasdqwdascfsdfvsdvwergvergerg",
                    "adsdcwegtryhyurtgwefwedwscsdcwsdfcasfwqedfwefsdfasdqwdascfsdfvsdvwergvergerg",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "lolskmzzzznzbxbxjxjjzkkzzkiziopoakidqoiwjdiqjhwdiqjwiodjdhjhbhbvhcebucbecercsdsd",
                    "Zlolskmzzzznzbxbxjxjjzkkzzkiziopoakidqoiwjdiqjhwdiqjwiodjdhjhbhbvhcebucbecercsdsd",
                    "aaaaaaaaaaaaaaaaaaaaa",
                    "kevthehermitisacompletegaywhatfuckwithhismotherXDXDXD",
                    "XXXXXXXkevthehermitisacompletegaywhatfuckwithhismotherXDXDXD",
                    ]
        raw_config = AlienSpy.decrypt_XOR(xor_keys, data)
        for line in raw_config.split('\n'):
            if line.startswith('<entry key'):
                config_dict[re.findall('key="(.*?)"', line)[0]] = re.findall('>(.*?)</entry', line)[0]
        return config_dict



    def get_config(self):
        """
        This is the main entry
        :return:
        """

        config_dict = False
        # Get name list for version detection
        namelist = self.file_info.zip_namelist()


        # Version B
        if 'ID' and 'MANIFEST.MF' in namelist:
            # Derive Key
            pre_key = self.file_info.file_from_zip('ID').decode('utf-8')
            enckey = ['{0}H3SUW7E82IKQK2J2J2IISIS'.format(pre_key)]
            # Decrypt
            coded_jar = self.file_info.file_from_zip('MANIFEST.MF')
            # Config
            config_dict = self.version_b(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'B'

        # Version C
        if 'resource/password.txt' and 'resource/server.dll' in namelist:
            pre_key = self.file_info.file_from_zip('resource/password.txt').decode('utf-8')
            enckey = ['CJDKSIWKSJDKEIUSYEIDWE{0}'.format(pre_key)]
            coded_jar = self.file_info.file_from_zip('resource/server.dll')
            config_dict = self.version_c(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'C'

        # Version D
        if 'java/stubcito.opp' and 'java/textito.isn' in namelist:
            pre_key = self.file_info.file_from_zip('java/textito.isn').decode('utf-8')
            enckey = ['TVDKSIWKSJDKEIUSYEIDWE{0}'.format(pre_key)]
            coded_jar = self.file_info.file_from_zip('java/stubcito.opp')
            config_dict = self.version_c(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'D'

        # Version E
        if 'java/textito.text' and 'java/resource.xsx' in namelist:
            pre_key = self.file_info.file_from_zip('java/textito.text').decode('utf-8')
            enckey = ['kevthehermitGAYGAYXDXD{0}'.format(pre_key)]
            coded_jar = self.file_info.file_from_zip('java/resource.xsx')
            config_dict = self.version_c(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'E'

        if 'amarillo/asdasd.asd' and 'amarillo/adqwdqwd.asdwf' in namelist:
            pre_key = self.file_info.file_from_zip('amarillo/asdasd.asd').decode('utf-8')
            enckey = ['kevthehermitGAYGAYXDXD{0}'.format(pre_key)]
            coded_jar = self.file_info.file_from_zip('amarillo/adqwdqwd.asdwf')
            config_dict = self.version_c(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'E2'

        # Version F
        if 'config/config.perl' in namelist:
            temp_config = self.xor_config(self.file_info.file_from_zip('config/config.perl'))
            coded_jar = self.file_info.file_from_zip(temp_config['SERVER'][1:])
            enckey = ['kevthehermitGAYGAYXDXD{0}'.format(temp_config["PASSWORD"])]
            config_dict = self.version_c(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'F'

        # Version G
        if 'config/config.pl' in namelist:
            temp_config = self.xor_config(self.file_info.file_from_zip('config/config.pl'))
            coded_jar = self.file_info.file_from_zip(temp_config['SERVER'][1:])
            enckey = ['kevthehermitGAYGAYGAYD{0}'.format(temp_config["PASSWORD"])]
            config_dict = self.version_c(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'G'

        # Version H
        if 'config/config.ini' in namelist:
            temp_config = self.xor_config(self.file_info.file_from_zip('config/config.ini'))
            coded_jar = self.file_info.file_from_zip(temp_config['SERVER'][1:])
            enckey = ['kevthehermitGAYGAYGAYD{0}'.format(temp_config["PASSWORD"]),
                      'kevthehermitGADGAYGAYD{}'.format(temp_config["PASSWORD"])]
            config_dict = self.version_c(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'H'

        # Version I
        if 'windows/windows.ini' in namelist:
            temp_config = self.xor_config(self.file_info.file_from_zip('windows/windows.ini'))
            coded_jar = self.file_info.file_from_zip(temp_config['SERVER'][1:])
            enckey = ['kevthehermitGADGAYGAYD{0}'.format(temp_config["PASSWORD"])]
            config_dict = self.version_c(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'I'

        # Version J
        if 'components/linux.plsk' in namelist:
            temp_config = self.xor_config(self.file_info.file_from_zip('components/linux.plsk'))
            coded_jar = self.file_info.file_from_zip(temp_config['SERVER'][1:])
            enckey = ['kevthehermitGADGAYGAYD{0}'.format(temp_config["PASSWORD"]),
                      'LDLDKFJVUI39OWIS9WOQ92{}'.format(temp_config["PASSWORD"])]
            config_dict = self.version_c(enckey, coded_jar)
            if config_dict is None:
                config_dict = self.version_d(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'J'

        # Version K
        if 'components/manifest.ini' in namelist:
            temp_config = self.xor_config(self.file_info.file_from_zip('components/manifest.ini'))
            coded_jar = self.file_info.file_from_zip(temp_config['SERVER'][1:])
            enckey = ['LDLDKFJVUI39OWIS9WOQ93{0}'.format(temp_config["PASSWORD"])]
            config_dict = self.version_d(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'K'

        # Version L
        if 'components/mac.hwid' in namelist:
            temp_config = self.xor_config(self.file_info.file_from_zip('components/mac.hwid'))
            coded_jar = self.file_info.file_from_zip(temp_config['SERVER'][1:])
            enckey = ['LDLDKFJVUI39OWIS9WOQ92{0}'.format(temp_config["PASSWORD"])]
            config_dict = self.version_d(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'L'

        # Version M
        if 'components/logo.png' in namelist:
            temp_config = self.xor_config(self.file_info.file_from_zip('components/logo.png'))
            coded_jar = self.file_info.file_from_zip(temp_config['SERVER'][1:])
            enckey = ['LDLDKFJVUI39OWIS9WOQ93{0}'.format(temp_config["PASSWORD"])]
            config_dict = self.version_d(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'M'

        # Version N
        if 'components/picture.gif' in namelist:
            temp_config = self.xor_config(self.file_info.file_from_zip('components/picture.gif'))
            coded_jar = self.file_info.file_from_zip(temp_config['SERVER'][1:])
            enckey = ['TDLDKFJVUI39OWIS9WOQ93{0}'.format(temp_config["PASSWORD"])]
            config_dict = self.version_d(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'N'

        # Version O
        if 'klip/clip.mp4' in namelist:
            temp_config = self.xor_config(self.file_info.file_from_zip('klip/clip.mp4'))
            coded_jar = self.file_info.file_from_zip(temp_config['SERVER'][1:])
            enckey = ['TKLDKFJVUI39OWIS9WOQ93{0}'.format(temp_config["PASSWORD"])]
            config_dict = self.version_d(enckey, coded_jar)
            # Add Version to Config
            config_dict['Version'] = 'O'




        # Update the config to the class for use
        if config_dict:
            self.config = config_dict
