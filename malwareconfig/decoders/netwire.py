import pefile
import yara
import struct

from malwareconfig.crypto import decrypt_arc4
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


rule_source = '''
rule opcodes {
  meta:
    description = "Netwire instruction sequences"
    author = "David Cannings"

  strings:
    $opcodes01 = { 31 C0 88 44 01 08 40 3D 00 01 00 00 75 F4 }
    $opcodes02 = { 8A 5C 06 08 88 9C 05 F4 FE FF FF 40 3D 00 01 00 00 75 ED }
    $opcodes03 = { 53 81 EC ?? ?? 00 00 C7 ?? ?? ?? ?? 00 00 00 C7 ?? ?? ?? ?? ?? ?? 00 8D ?? ?? ?? FF FF 89 ?? ?? E8 ?? ?? ?? 00 }
    $opcodes04 = { E8 ?? ?? 00 00 C7 44 ?? ?? ?? ?? 00 00 C7 44 ?? ?? ?? ?? ?? 00 89 ?? ?? E8 ?? ?? ?? 00 }
    $opcodes05 = { 53 81 EC ?? ?? 00 00 ?? ?? ?? ?? C7 ?? ?? ?? ?? 00 00 00 C7 ?? ?? ?? ?? ?? ?? 00 8? ?? ?? E8 ?? ?? ?? 00 }
    $opcodes06 = { E8 ?? ?? 00 00 ?? ?? ?? C7 44 ?? ?? ?? ?? 00 00 C7 44 ?? ?? ?? ?? ?? 00 E8 ?? ?? ?? 00 }

  condition:
    2 of them
}
'''

class NetWire(Decoder):
    decoder_name = "NetWire"
    decoder__version = 1
    decoder_author = "@kevthehermit & David Cannings"
    decoder_description = "Netwire decoder"

    def __init__(self):
        self.config = {}

    def pe_data(self, pe, va, size):
        image_base = pe.OPTIONAL_HEADER.ImageBase
        rva = va - image_base
        data = pe.get_data(rva, size)
        return data

    def yara_scan(self, raw_data, rule_name):
        yara_data = []
        yara_rules = yara.compile(source=rule_source)
        matches = yara_rules.match(data=raw_data)
        for match in matches:
            if match.rule == 'opcodes':
                for item in match.strings:
                    if item[1] == rule_name:
                        data = item[2]
                        yara_data.append(data)
        return yara_data

    def parse_options(self, option_data):
        out = []

        options = {
            0x01: "Copy executable",
            0x02: "Delete original",
            0x04: "Lock executable",
            0x08: "Registry autorun",
            0x10: "ActiveX autorun",
            0x20: "Use a mutex",
            0x40: "Offline keylogger"
        }

        for k in options.keys():
            enabled = (int(option_data) & k) != 0
            out.append({'Option': options[k], 'Value': enabled})

        return out

    def proxy_options(self, option_data):
        proxy_setting = {
            1: "Direct connection",
            2: "Single proxy",
            4: "Proxy chain"
        }
        return proxy_setting[int(option_data)]

    def parse_config(self, config_list):
        config_dict = {}
        domain_list = config_list[0].decode('utf-8').rstrip(';').split(';')
        config_dict['Domains'] = domain_list
        if config_list[1] == b'-':
            config_dict['Proxy Server'] = 'Not Configured'
        else:
            proxy_list = []
            proxy_type = ["socks4", "socks4a", "socks5", "http"]
            for server in config_list[1].decode('utf-8').rstrip(';').split(';'):
                p = server.split(':')
                if len(p) < 2:
                    return({})
                i = int(p[2])
                proxy_list.append('{0}:{1}:{2}'.format(proxy_type[i], p[0], p[1]))
            config_dict['Proxy Server'] = proxy_list

        config_dict['Password'] = config_list[2]
        config_dict['Host ID'] = config_list[3]
        config_dict['Mutex'] = config_list[4]
        config_dict['Install Path'] = config_list[5]
        config_dict['Startup Name'] = config_list[6]
        config_dict['ActiveX Key'] = config_list[7]
        config_dict['KeyLog Dir'] = config_list[8]
        config_dict['Proxy Option'] = self.proxy_options(config_list[10])
        for o in self.parse_options(config_list[9]):
            config_dict[o['Option']] = o['Value']
        
        return config_dict
    

    def parse_domains(self, domains):
        domain_list = []
        for domain in domains:
            domain_list.append(domain.split(':')[0])
        return domain_list


    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        file_data = self.file_info.file_data

        pe = pefile.PE(data=file_data, fast_load=False)

        data = self.yara_scan(file_data, '$opcodes03')

        try:
            key_va = struct.unpack('i', data[0][19:23])[0]
        except:
            data = self.yara_scan(file_data, '$opcodes05')
            key_va = struct.unpack('<i', data[0][23:27])[0]
        key_hex = self.pe_data(pe, key_va, 16)


        data_2 = self.yara_scan(file_data, '$opcodes04')

        config_list = []
        for section in data_2:
            length = struct.unpack('i', section[9:13])[0]
            data_va = struct.unpack('i', section[17:21])[0]
            sec_data = self.pe_data(pe, data_va, length)
            dec = decrypt_arc4(key_hex, sec_data)
            if b'\x00' in dec:
                dec = dec[:dec.index(b'\x00')]
            config_list.append(dec)

        config_dict = self.parse_config(config_list)
        #Check for new version
        if config_dict == {}:
            print("New Version Check")
            data_2 = self.yara_scan(file_data, '$opcodes06')
            config_list = []
            for section in data_2:
                length = struct.unpack('i', section[12:16])[0]
                data_va = struct.unpack('i', section[20:24])[0]
                sec_data = self.pe_data(pe, data_va, length)
                dec = decrypt_arc4(key_hex, sec_data)
                if b'\x00' in dec:
                    dec = dec[:dec.index(b'\x00')]
                config_list.append(dec)

            config_dict = self.parse_config(config_list)

        self.config = config_dict
