from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable

from binascii import hexlify, unhexlify

# temp imports
import re
from struct import unpack

class Xtreme(Decoder):
    decoder_name = "Xtreme"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "Xtreme decoder for 2.9, 3.1, 3.2, 3.5"

    def __init__(self):
        self.config = {}

    def get_unicode_string(self, buf, pos):
        out = ''
        for i in range(len(buf[pos:])):
            if buf[pos+i] == 0 and buf[pos+i+1] == 0:
                out += '\x00'
                break
            out += chr(buf[pos+i])
        if out == '':
            return None
        else:
            return out.replace('\x00','')


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''
        
        raw_config = {}
        file_data = self.file_info.file_data

        # Get Resource
        res_data = self.file_info.pe_resource_id(b'X\x00T\x00R\x00E\x00M\x00E\x00')


        # Return no resource
        if not res_data:
            print("  [-] No Config Resource Found")
            return # Check what we do for a negative result


        key = 'C\x00O\x00N\x00'
        decrypted_config = crypto.decrypt_arc4(key, res_data)
    
        # 1.3.x - Not implemented yet.
        if len(decrypted_config) == 0xe10:
            config_data = None
        # 2.9.x - Not a stable extract.
        elif len(decrypted_config) == 0x1390 or len(decrypted_config) == 0x1392:
            config_data = self.v29(decrypted_config)
        # 3.1 & 3.2
        elif len(decrypted_config) == 0x5Cc:
            config_data = self.v32(decrypted_config)
        # 3.5
        elif len(decrypted_config) == 0x7f0:
            config_data = self.v35(decrypted_config)
        else:
            config_data = None

    
    def v29(self, rawConfig):
        config_data = {}
        config_data["ID"] = self.get_unicode_string(rawConfig, 0x9e0)
        config_data["Group"] = self.get_unicode_string(rawConfig, 0xa5a)
        config_data["Version"] = self.get_unicode_string(rawConfig, 0xf2e)
        config_data["Mutex"] = self.get_unicode_string(rawConfig, 0xfaa)
        config_data["Install Dir"] = self.get_unicode_string(rawConfig, 0xb50)
        config_data["Install Name"] = self.get_unicode_string(rawConfig, 0xad6)
        config_data["HKLM"] = self.get_unicode_string(rawConfig, 0xc4f)
        config_data["HKCU"] = self.get_unicode_string(rawConfig, 0xcc8)
        config_data["Custom Reg Key"] = self.get_unicode_string(rawConfig, 0xdc0)
        config_data["Custom Reg Name"] = self.get_unicode_string(rawConfig, 0xe3a)
        config_data["Custom Reg Value"] = self.get_unicode_string(rawConfig, 0xa82)
        config_data["ActiveX Key"] = self.get_unicode_string(rawConfig, 0xd42)
        config_data["Injection"] = self.get_unicode_string(rawConfig, 0xbd2)
        config_data["FTP Server"] = self.get_unicode_string(rawConfig, 0x111c)
        config_data["FTP UserName"] = self.get_unicode_string(rawConfig, 0x1210)
        config_data["FTP Password"] = self.get_unicode_string(rawConfig, 0x128a)
        config_data["FTP Folder"] = self.get_unicode_string(rawConfig, 0x1196)
        config_data["Domain1"] = str(self.get_unicode_string(rawConfig, 0x50)+":"+str(unpack("<I", rawConfig[0:4])[0]))
        config_data["Domain2"] = str(self.get_unicode_string(rawConfig, 0xca)+":"+str(unpack("<I", rawConfig[4:8])[0]))
        config_data["Domain3"] = str(self.get_unicode_string(rawConfig, 0x144)+":"+str(unpack("<I", rawConfig[8:12])[0]))
        config_data["Domain4"] = str(self.get_unicode_string(rawConfig, 0x1be)+":"+str(unpack("<I", rawConfig[12:16])[0]))
        config_data["Domain5"] = str(self.get_unicode_string(rawConfig, 0x238)+":"+str(unpack("<I", rawConfig[16:20])[0]))
        config_data["Domain6"] = str(self.get_unicode_string(rawConfig, 0x2b2)+":"+str(unpack("<I", rawConfig[20:24])[0]))
        config_data["Domain7"] = str(self.get_unicode_string(rawConfig, 0x32c)+":"+str(unpack("<I", rawConfig[24:28])[0]))
        config_data["Domain8"] = str(self.get_unicode_string(rawConfig, 0x3a6)+":"+str(unpack("<I", rawConfig[28:32])[0]))
        config_data["Domain9"] = str(self.get_unicode_string(rawConfig, 0x420)+":"+str(unpack("<I", rawConfig[32:36])[0]))
        config_data["Domain10"] = str(self.get_unicode_string(rawConfig, 0x49a)+":"+str(unpack("<I", rawConfig[36:40])[0]))
        config_data["Domain11"] = str(self.get_unicode_string(rawConfig, 0x514)+":"+str(unpack("<I", rawConfig[40:44])[0]))
        config_data["Domain12"] = str(self.get_unicode_string(rawConfig, 0x58e)+":"+str(unpack("<I", rawConfig[44:48])[0]))
        config_data["Domain13"] = str(self.get_unicode_string(rawConfig, 0x608)+":"+str(unpack("<I", rawConfig[48:52])[0]))
        config_data["Domain14"] = str(self.get_unicode_string(rawConfig, 0x682)+":"+str(unpack("<I", rawConfig[52:56])[0]))
        config_data["Domain15"] = str(self.get_unicode_string(rawConfig, 0x6fc)+":"+str(unpack("<I", rawConfig[56:60])[0]))
        config_data["Domain16"] = str(self.get_unicode_string(rawConfig, 0x776)+":"+str(unpack("<I", rawConfig[60:64])[0]))
        config_data["Domain17"] = str(self.get_unicode_string(rawConfig, 0x7f0)+":"+str(unpack("<I", rawConfig[64:68])[0]))
        config_data["Domain18"] = str(self.get_unicode_string(rawConfig, 0x86a)+":"+str(unpack("<I", rawConfig[68:72])[0]))
        config_data["Domain19"] = str(self.get_unicode_string(rawConfig, 0x8e4)+":"+str(unpack("<I", rawConfig[72:76])[0]))
        config_data["Domain20"] = str(self.get_unicode_string(rawConfig, 0x95e)+":"+str(unpack("<I", rawConfig[76:80])[0]))
        self.config = config_data
    
    
    def v32(self, rawConfig):
        config_data = {}
        config_data["ID"] = self.get_unicode_string(rawConfig, 0x1b4)
        config_data["Group"] = self.get_unicode_string(rawConfig, 0x1ca)
        config_data["Version"] = self.get_unicode_string(rawConfig, 0x2bc)
        config_data["Mutex"] = self.get_unicode_string(rawConfig, 0x2d4)
        config_data["Install Dir"] = self.get_unicode_string(rawConfig, 0x1f8)
        config_data["Install Name"] = self.get_unicode_string(rawConfig, 0x1e2)
        config_data["HKLM"] = self.get_unicode_string(rawConfig, 0x23a)
        config_data["HKCU"] = self.get_unicode_string(rawConfig, 0x250)
        config_data["ActiveX Key"] = self.get_unicode_string(rawConfig, 0x266)
        config_data["Injection"] = self.get_unicode_string(rawConfig, 0x216)
        config_data["FTP Server"] = self.get_unicode_string(rawConfig, 0x35e)
        config_data["FTP UserName"] = self.get_unicode_string(rawConfig, 0x402)
        config_data["FTP Password"] = self.get_unicode_string(rawConfig, 0x454)
        config_data["FTP Folder"] = self.get_unicode_string(rawConfig, 0x3b0)
        config_data["Domain1"] = str(self.get_unicode_string(rawConfig, 0x14)+":"+str(unpack("<I", rawConfig[0:4])[0]))
        config_data["Domain2"] = str(self.get_unicode_string(rawConfig, 0x66)+":"+str(unpack("<I", rawConfig[4:8])[0]))
        config_data["Domain3"] = str(self.get_unicode_string(rawConfig, 0xb8)+":"+str(unpack("<I", rawConfig[8:12])[0]))
        config_data["Domain4"] = str(self.get_unicode_string(rawConfig, 0x10a)+":"+str(unpack("<I", rawConfig[12:16])[0]))
        config_data["Domain5"] = str(self.get_unicode_string(rawConfig, 0x15c)+":"+str(unpack("<I", rawConfig[16:20])[0]))
        config_data["Msg Box Title"] = self.get_unicode_string(rawConfig, 0x50c)
        config_data["Msg Box Text"] = self.get_unicode_string(rawConfig, 0x522)
        self.config = config_data
    
    
    def v35(self, config_raw):
        config_data = {}
        config_data['ID'] = self.get_unicode_string(config_raw, 0x1b4)
        config_data['Group'] = self.get_unicode_string(config_raw, 0x1ca)
        config_data['Version'] = self.get_unicode_string(config_raw, 0x2d8)
        config_data['Mutex'] = self.get_unicode_string(config_raw, 0x2f0)
        config_data['Install Dir'] = self.get_unicode_string(config_raw, 0x1f8)
        config_data['Install Name'] = self.get_unicode_string(config_raw, 0x1e2)
        config_data['HKLM'] = self.get_unicode_string(config_raw, 0x23a)
        config_data['HKCU'] = self.get_unicode_string(config_raw, 0x250)
        config_data['ActiveX Key'] = self.get_unicode_string(config_raw, 0x266)
        config_data['Injection'] = self.get_unicode_string(config_raw, 0x216)
        config_data['FTP Server'] = self.get_unicode_string(config_raw, 0x380)
        config_data['FTP UserName'] = self.get_unicode_string(config_raw, 0x422)
        config_data['FTP Password'] = self.get_unicode_string(config_raw, 0x476)
        config_data['FTP Folder'] = self.get_unicode_string(config_raw, 0x3d2)
        config_data['Domain1'] = str(self.get_unicode_string(config_raw, 0x14)+':'+str(unpack('<I', config_raw[0:4])[0]))
        config_data['Domain2'] = str(self.get_unicode_string(config_raw, 0x66)+':'+str(unpack('<I', config_raw[4:8])[0]))
        config_data['Domain3'] = str(self.get_unicode_string(config_raw, 0xb8)+':'+str(unpack('<I', config_raw[8:12])[0]))
        config_data['Domain4'] = str(self.get_unicode_string(config_raw, 0x10a)+':'+str(unpack('<I', config_raw[12:16])[0]))
        config_data['Domain5'] = str(self.get_unicode_string(config_raw, 0x15c)+':'+str(unpack('<I', config_raw[16:20])[0]))
        config_data['Msg Box Title'] = self.get_unicode_string(config_raw, 0x52c)
        config_data['Msg Box Text'] = self.get_unicode_string(config_raw, 0x542)
        self.config = config_data
