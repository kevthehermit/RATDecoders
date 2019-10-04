from malwareconfig.crypto import decrypt_arc4
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable
from binascii import unhexlify

class LostDoor(Decoder):
    decoder_name = "LostDoor"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "LostDoor Rat"

    def __init__(self):
        self.config = {}


    def ver_detect(self, data):
        first = data.split(b"*EDIT_SERVER*")
        if len(first) == 2:
            second = first[1].split(b"\r\n")
            if len(second) > 14 < 30:
                print("[+] Found Version < 8")
                return self.new_decoder(second)
        first = data.split(b"[DATA]")
        if len(first) == 21:
            print("[+] Found Version 8")
            return self.ver_80(first)
        if len(first) == 30:
            print("[+] Found Version 8.01")
            return self.ver_801(first)
        return None

    def new_decoder(self, split_list):
        raw_dict = {}
        for line in split_list:
            try:
                line = line.decode('UTF-8')
                k,v = line.split(' = ')
                raw_dict[k.strip('*')] = v.strip('%')
            except Exception as e:
                continue
        return self.config_cleaner(raw_dict)

    def config_cleaner(self, raw_dict):
        clean_dict = {}
        for k,v in raw_dict.items():
            if k == 'ip':
                clean_dict['Domain'] = decrypt_arc4('oussamio', unhexlify(v))
            if k == 'fire':
                clean_dict['Firewall Bypass'] = v
            if k == 'foder':
                clean_dict['InstallPath'] = v
            if k == 'mlt':
                clean_dict['Melt'] = v
            if k == 'msns':
                clean_dict['MSN Spread'] = v
            if k == 'name':
                clean_dict['Reg Key'] = v
            if k == 'path':
                clean_dict['Reg value'] = v
            if k == 'port':
                clean_dict['Port'] = v
            if k == 'ppp':
                clean_dict['P2PSpread'] = v
            if k == 'reg':
                clean_dict['Registry Startup'] = v
            if k == 'usb':
                clean_dict['USB Spread'] = v
            if k == 'usbn':
                clean_dict['USB Name'] = v
            if k == 'victimo':
                clean_dict['Campaign'] = v
        return clean_dict

    @staticmethod
    def ver_80(conf):
        conf_dict = {}
        conf_dict['Domain'] = decrypt_arc4('UniQue OussamiO', unhexlify(conf[1]))
        conf_dict['Campaign'] = conf[2]
        conf_dict['Enable Startup'] = conf[3]
        conf_dict['StartupName'] = conf[4]
        conf_dict['FolderName'] = conf[5]
        if conf[6] == "D":
            conf_dict['Path'] = 'App Data Folder'
        elif conf[6] == "W":
            conf_dict['Path'] = 'Windows Folder'
        if conf[6] == "s":
            conf_dict['Path'] = 'System Folder'
        conf_dict['Enable Error Message'] = conf[7]
        conf_dict['Error Message'] = conf[8]
        conf_dict['Disable Firewall'] = conf[9]
        #conf_dict[''] = conf[10]
        #conf_dict[''] = conf[11]
        conf_dict['USB Spread'] = conf[12]
        conf_dict['MSN Spread'] = conf[13]
        conf_dict['P2P Spread'] = conf[14]
        conf_dict['Melt'] = conf[15]
        conf_dict['Get Default User Name'] = conf[16]
        conf_dict['Connection Delay'] = conf[17]
        conf_dict['Set Hidden'] = conf[18]
        conf_dict['Protect Process'] = conf[19]
        #conf_dict[''] = conf[20]

        return conf_dict
        
    @staticmethod
    def ver_801(conf):
        conf_dict = {}
        conf_dict['Domain'] = decrypt_arc4('UniQue OussamiO', conf[1])
        conf_dict['Campaign'] = conf[2]
        conf_dict['Enable Startup'] = conf[3]
        conf_dict['StartupName'] = conf[4]
        conf_dict['FolderName'] = conf[5]
        if conf[6] == 'D':
            conf_dict['Path'] = 'App Data Folder'
        elif conf[6] == 'W':
            conf_dict['Path'] = 'Windows Folder'
        if conf[6] == 's':
            conf_dict['Path'] = 'System Folder'
        conf_dict['Enable Error Message'] = conf[7]
        conf_dict['Error Message'] = conf[8]
        conf_dict['Disable Firewall'] = conf[9]
        conf_dict['USB Spread'] = conf[12]
        conf_dict['MSN Spread'] = conf[13]
        conf_dict['P2P Spread'] = conf[14]
        conf_dict['Melt'] = conf[15]
        conf_dict['Get Default User Name'] = conf[16]
        conf_dict['Connection Delay'] = conf[17]
        conf_dict['Set Hidden'] = conf[18]
        conf_dict['Protect Process'] = conf[19]
        conf_dict['Name To Spread'] = conf[20]
        conf_dict['Enable Active X'] = conf[21]
        conf_dict['Active X Key'] = conf[22]
        conf_dict['Enable Mutex'] = conf[23]
        conf_dict['Mutex'] = conf[24]
        conf_dict['Persistant Server'] = conf[25]
        conf_dict['Offline Keylogger'] = conf[26]
        conf_dict['Disable Task Manager'] = conf[27]
        conf_dict['Disable RegEdit'] = conf[28]
        return conf_dict




    def get_config(self):
        '''
        This is the main entry
        :return:
        '''


        file_data = self.file_info.file_data

        config_dict = self.ver_detect(file_data)

        # Set the config to the class for use
        self.config = config_dict
