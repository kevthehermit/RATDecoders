from base64 import b64decode
from binascii import unhexlify, hexlify

from malwareconfig import crypto
from malwareconfig.common import Decoder


class HawkEye(Decoder):
    decoder_name = "HawkEye"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Decoder For Hawkeye Cred Stealer"

    def __init__(self):
        self.config = {}

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        # Get the user string list
        user_strings = self.file_info.dotnet_user_strings()

        # Version Check

        key = 'HawkEyeKeylogger'
        salt = '0\x009\x009\x00u\x007\x008\x007\x009\x007\x008\x007\x008\x006\x00'

        # Older Version
        if 'InvisibleSoft' in user_strings:
            key = 'InvisibleSoft'

        # Derive Key
        d_iv, d_key = crypto.derive_pbkdf2(key, salt, 16, 32, iterations=1000)

        # base key = HawkEyeKeylogger
        # iv = 68884763241455010e730a43249fdf87
        # Key = 20eec1151ad79610fa5def0ef4fe701c87f1699c163d7e4dc2be0da50f661b53

        # Grab values and decrypt the encoded one.

        raw_config = {}
        for i in range(3,40):
            try:
                crypted_string = b64decode(user_strings[i])
                result = crypto.decrypt_aes_cbc_iv(d_key, d_iv, crypted_string)
                result = result.decode('utf-8')

                # There are some padding chars
                for rep in ['\x00', '\n', '\x08', '\x04', '\x10']:
                    result = result.replace(rep, '')

                raw_config['Key{0}'.format(i)] = result

            except Exception as e:
                raw_config['Key{0}'.format(i)] = user_strings[i]

        # Set the config to the class for use
        self.config = raw_config
