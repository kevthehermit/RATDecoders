from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable

from binascii import hexlify, unhexlify

# temp imports
import re
import zlib
import uuid
from struct import unpack

class NanoCore(Decoder):
    decoder_name = "NanoCore"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "NanoCore decoder for early versions"

    def __init__(self):
        self.config = {}

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        dotnet_res_names = self.file_info.dotnet_resource_names()
        pe_res_names = self.file_info.pe_resource_names()

        # Get Resource
        res_data = False
        if b'Data.bin' in dotnet_res_names:
            res_data = self.file_info.dotnet_resource_by_name(b'Data.bin')
        elif len(pe_res_names) == 1:
            res_data = self.file_info.pe_resource_id(pe_res_names[0])
        else:
            res_data = self.file_info.pe_resource_id(1)


        # Return no resource
        if not res_data:
            print("  [-] No Config Resource Found")
            return # Check what we do for a negative result


        # What Version are we on

        if res_data[0:4] == b'\x08\x00\x00\x00':
            conf_dict = self.decrypt_v2(res_data)
            
        elif res_data[0:4] == b'\x10\x00\x00\x00':
            # we need to derive a key from teh assembly guid
            guid = self.file_info.dotnet_guids()[1]
            #guid = re.search(b'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', file_data).group()
            #print(guid)
            guid = uuid.UUID(guid).bytes_le
            encrypted_key = res_data[4:20]
            # rfc2898 derive bytes
            #derived_key = derive_key(guid, encrypted_key)
            div, dkey = crypto.derive_pbkdf2(guid, guid, 16, 16, iterations=8)
            final_key = crypto.decrypt_aes_cbc_iv(dkey, div, encrypted_key)

            conf_dict = self.decrypt_v3(res_data, final_key)
        else:
           conf_dict = self.decrypt_v1(res_data)
        return conf_dict


    def decrypt_v3(self, coded_config, key):
        data = coded_config[24:]
        decrypt_key = key[:8]
        raw_config = crypto.decrypt_des_cbc(decrypt_key, data, iv=decrypt_key)
        # if the config is over a certain size it is compressed. Indicated by a non Null byte

        if raw_config[1] == 0:
            return self.parse_config(raw_config, '3')
        else:
            # remove the string lengths and deflate the remainder of the stream
            deflate_config = self.deflate_contents(raw_config)
            return self.parse_config(deflate_config, '3')

    def decrypt_v2(self, coded_config):
        key = coded_config[4:12]
        data = coded_config[16:]
        raw_config = crypto.decrypt_des_cbc(key, data, iv=key)
        # if the config is over a certain size it is compressed. Indicated by a non Null byte
        if raw_config[1] == 0:
            return self.parse_config(raw_config, '2')
        else:
            # remove the string lengths and deflate the remainder of the stream
            deflate_config = self.deflate_contents(raw_config)
            return self.parse_config(deflate_config, '2')
                
    def decrypt_v1(self, coded_config):
        key = '\x01\x03\x05\x08\x0d\x15\x22\x37'
        data = coded_config[1:]
        new_data = crypto.decrypt_des_cbc(key, data, iv=key)
        if new_data[0] != 0:
            deflate_config = self.deflate_contents(new_data)
            return self.parse_config(deflate_config, 'old')

    def deflate_contents(self, data):
        new_data = data[5:]
        return zlib.decompress(new_data, -15)

    # returns pretty config
    def parse_config(self, raw_config, ver):
        config_dict = {}
        
        # Some plugins drop in here as exe files. 
        if b'This program cannot be run' in raw_config:
            if b'BuildTime' in raw_config:
                raw_config = raw_config.split(b'BuildTime')[1]
            else:
                raw_config = raw_config.split(b'INSTALL_TITLE')[1]

        
        if ver == '2':
            #config_dict['BuildTime'] = unpack(">Q", re.search(b'BuildTime(.*?)\x0c', raw_config).group()[10:-1])[0]
            config_dict['Version'] = re.search(b'Version\x0c(.*?)\x0c', raw_config).group()[8:-1]
            config_dict['Mutex'] = re.search(b'Mutex(.*?)\x0c', raw_config).group()[6:-1]
            config_dict['Group'] = re.search(b'DefaultGroup\x0c(.*?)\x0c', raw_config).group()[14:-1]
            config_dict['Domain1'] = re.search(b'PrimaryConnectionHost\x0c(.*?)Back', raw_config, re.DOTALL).group()[23:-6]
            config_dict['Domain2'] = re.search(b'BackupConnectionHost\x0c(.*?)\x0c', raw_config).group()[22:-1]
            config_dict['Port'] = unpack("<H", re.search(b'ConnectionPort...', raw_config, re.DOTALL).group()[15:])[0]
            config_dict['RunOnStartup'] = re.search(b'RunOnStartup(.*?)\x0c', raw_config).group()[13:-1]
            config_dict['RequestElevation'] = re.search(b'RequestElevation(.*?)\x0c', raw_config).group()[17:-1]
            config_dict['BypassUAC'] = re.search(b'BypassUserAccountControl(.*?)\x0c', raw_config).group()[25:-1]
            config_dict['ClearZoneIdentifier'] = re.search(b'ClearZoneIdentifier(.*?)\x0c', raw_config).group()[20:-1]
            config_dict['ClearAccessControl'] = re.search(b'ClearAccessControl(.*?)\x0c', raw_config).group()[19:-1]
            config_dict['SetCriticalProcess'] = re.search(b'SetCriticalProcess(.*?)\x0c', raw_config).group()[19:-1]
            config_dict['FindLanServers'] = re.search(b'FindLanServers(.*?)\x0c', raw_config).group()[15:-1]
            config_dict['RestartOnException'] = re.search(b'RestartOnException(.*?)\x0c', raw_config).group()[19:-1]
            config_dict['EnableDebugMode'] = re.search(b'EnableDebugMode(.*?)\x0c', raw_config).group()[16:-1]
            config_dict['ConnectDelay'] = unpack("<i", re.search(b'ConnectDelay(.*?)\x0c', raw_config).group()[13:-1])[0]
            config_dict['RestartDelay'] = unpack("<i", re.search(b'RestartDelay(.*?)\x0c', raw_config).group()[13:-1])[0]
        elif ver == '3':
            config_dict['Version'] = re.search(b'Version..(.*?)\x0c', raw_config).group()[8:16]
            config_dict['Mutex'] = re.search(b'Mutex(.*?)\x0c', raw_config).group()[6:-1]
            config_dict['Group'] = re.search(b'DefaultGroup\x0c(.*?)\x0c', raw_config).group()[14:-1]
            config_dict['Domain1'] = re.search(b'PrimaryConnectionHost\x0c(.*?)Back', raw_config, re.DOTALL).group()[23:-6]
            config_dict['Domain2'] = re.search(b'BackupConnectionHost\x0c(.*?)\x0c', raw_config).group()[22:-1]
            config_dict['Port'] = unpack("<H", re.search(b'ConnectionPort...', raw_config, re.DOTALL).group()[15:])[0]
            config_dict['RunOnStartup'] = re.search(b'RunOnStartup(.*?)\x0c', raw_config).group()[13:-1]
            config_dict['RequestElevation'] = re.search(b'RequestElevation(.*?)\x0c', raw_config).group()[17:-1]
            config_dict['BypassUAC'] = re.search(b'BypassUserAccountControl(.*?)\x0c', raw_config).group()[25:-1]
            config_dict['ClearZoneIdentifier'] = re.search(b'ClearZoneIdentifier(.*?)\x0c', raw_config).group()[20:-1]
            config_dict['ClearAccessControl'] = re.search(b'ClearAccessControl(.*?)\x0c', raw_config).group()[19:-1]
            config_dict['SetCriticalProcess'] = re.search(b'SetCriticalProcess(.*?)\x0c', raw_config).group()[19:-1]
            config_dict['PreventSystemSleep'] = re.search(b'PreventSystemSleep(.*?)\x0c', raw_config).group()[19:-1]

            config_dict['EnableDebugMode'] = re.search(b'EnableDebugMode(.*?)\x0c', raw_config).group()[16:-1]

            try:
                config_dict['ConnectDelay'] = unpack("<i", re.search(b'ConnectDelay(.*?)\x0c', raw_config).group()[13:-1])[0]
                config_dict['RestartDelay'] = unpack("<i", re.search(b'RestartDelay(.*?)\x0c', raw_config).group()[13:-1])[0]
            except:
                pass
                #config_dict['RunDelay'] = unpack("<i", re.search(b'RunDelay(.*?)\x0c', raw_config).group()[7:-1])[0]

            try:
                config_dict['UseCustomDNS'] = re.search(b'UseCustomDnsServer(.*?)\x0c', raw_config).group()[19:-1]
                config_dict['PrimaryDNSServer'] = re.search(b'PrimaryDnsServer\x0c(.*?)\x0c', raw_config).group()[18:-1]
                config_dict['BackupDNSServer'] = re.search(b'BackupDnsServer\x0c(.*?)(\x04|\x0c)', raw_config).group()[16:-1]
            except:
                pass

            try:
                config_dict['CountryCode'] = re.search(b'CountryCode\x0c(.*?)\x0c', raw_config).group()[12:-1]
                config_dict['HWID'] = re.search(b'Hwid\x0c(.*?)\x0c', raw_config).group()[5:-1]
            except Exception as e:
                pass

        else:
            config_dict['Domain'] = re.search(b'HOST\x0c(.*?)\x0c', raw_config).group()[6:-1]
            config_dict['Port'] = unpack("<H", re.search(b'PORT(.*?)\x0c', raw_config).group()[5:-1])[0]
            config_dict['Group'] = re.search(b'GROUP\x0c(.*?)\x0c', raw_config).group()[7:-1]
            config_dict['ConnectDelay'] = unpack("<i", re.search(b'DELAY(.*?)\x0c', raw_config).group()[6:-1])[0]
            config_dict['OfflineKeyLog'] = str(re.search(b'OFFLINE_KEYLOGGING(.*?)\x0c', raw_config).group()[19:-1])

        self.config = config_dict