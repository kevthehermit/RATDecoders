from binascii import unhexlify
from base64 import b64decode
from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig import fileparser


class JRat(Decoder):
    decoder_name = "JRat"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Java Based RAT"

    def __init__(self):
        self.config = {}


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        file_info = self.file_info
        file_list = file_info.zip_namelist()

        internal_jar = None
        key_file = None
        config_data = None

        config_dict = {}

        for name in file_list:
            if name == 'key.dat':
                key_file = file_info.file_from_zip(name)
            if name == 'enc.dat':
                internal_jar = file_info.file_from_zip(name)
            if name == 'config.dat':
                config_data = file_info.file_from_zip(name)

        # If there is a wrapper around the jrat
        if internal_jar:
            drop_conf = key_file
            new_key = drop_conf[:16]
            drop_conf_fields = key_file[16:].split(b',')
            config_dict['dropper'] = []
            for field in drop_conf_fields:
                try:
                    decoded_field = b64decode(field).decode('utf-8')
                    config_dict['dropper'].append(unhexlify(decoded_field))
                except:
                    pass

            new_jar_data = crypto.decrypt_aes(new_key, internal_jar)
            new_jar = fileparser.FileParser(rawdata=new_jar_data)

            # replace the keyfile and jar file with the new dropper
            for name in new_jar.zip_namelist():
                if name == 'key.dat':
                    key_file = new_jar.file_from_zip(name)
                if name == 'config.dat':
                    config_data = new_jar.file_from_zip(name)


        # With the Key and Config Decrypt
        if len(key_file) == 16:
            # AES
            decrypted = crypto.decrypt_aes(key_file, config_data)

        if len(key_file) in [24, 32]:
            decrypted = crypto.decrypt_des3(key_file, config_data)


        # Process the decrypted Config

        decrypted = decrypted.decode('utf-8')

        # Clean it up a little
        for c in ['\x01', '\x03', '\x04', '\x06', '\x08']:
            decrypted = decrypted.replace(c, '')

        fields = decrypted.split('SPLIT')



        for field in fields:
            if '=' not in field:
                continue
            key, value = field.split('=')

            if key == 'ip':
                config_dict['Domain'] = value
            if key == 'addresses':
                dom_list = value.split(',')
                dom_count = 0
                for dom in dom_list:
                    if dom == '':
                        continue
                    config_dict['Domain {0}'.format(dom_count)] = value.split(':')[0]
                    config_dict['Port {0}'.format(dom_count)] = value.split(':')[1]
                    dom_count += 1
            if key == 'port':
                config_dict['Port'] = value
            if key == 'os':
                config_dict['OS'] = value
            if key == 'mport':
                config_dict['MPort'] = value
            if key == 'perms':
                config_dict['Perms'] = value
            if key == 'error':
                config_dict['Error'] = value
            if key == 'reconsec':
                config_dict['RetryInterval'] = value
            if key == 'ti':
                config_dict['TI'] = value
            if key == 'pass':
                config_dict['Password'] = value
            if key == 'id':
                config_dict['CampaignID'] = value
            if key == 'mutex':
                config_dict['Mutex'] = value
            if key == 'toms':
                config_dict['TimeOut'] = value
            if key == 'per':
                config_dict['Persistance'] = value
            if key == 'name':
                config_dict['InstallName'] = value
            if key == 'tiemout':
                config_dict['TimeOutFlag'] = value
            if key == 'debugmsg':
                config_dict['DebugMsg'] = value
        config_dict["EncryptionKey"] = key_file






        # Set the config to the class for use
        self.config = config_dict
