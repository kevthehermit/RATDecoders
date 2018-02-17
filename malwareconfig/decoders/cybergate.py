from malwareconfig import crypto
from malwareconfig.common import Decoder
from malwareconfig.common import string_printable


class CyberGate(Decoder):
    decoder_name = "CyberGate"
    decoder__version = 1
    decoder_author = "@kevthehermit"
    decoder_description = "CyberGate RAT"

    def __init__(self):
        self.config = {}

    @staticmethod
    def xor(data):
        decoded = ''
        key = 0xBC
        for c in data:
            decoded += chr(key^c)
        return decoded

    def get_config(self):
        '''
        This is the main entry
        :return:
        '''

        key = 0xBC

        resource_list = self.file_info.pe_resource_names()

        if 'XX-XX-XX-XX' in resource_list:
            config_data = self.file_info.pe_resource_by_name('XX-XX-XX-XX')
        elif 'CG-CG-CG-CG' in resource_list:
            config_data = self.file_info.pe_resource_by_name('CG-CG-CG-CG')
        else:
            print("Unable to find config data")
            return

        fields = config_data.split(b'####@####')
        config_dict = {}
        # fields 0 - 19 contain domains and ports
        for i in range(19):
            decrypted = CyberGate.xor(fields[i])
            if decrypted == '\x9c':
                continue
            config_dict['Domain{0}'.format(i)] = decrypted
        
        config_dict['CampaignID'] = CyberGate.xor(fields[20])
        config_dict['Password'] = CyberGate.xor(fields[21])
        config_dict['InstallFlag'] = CyberGate.xor(fields[22])
        config_dict['InstallDir'] = CyberGate.xor(fields[25])
        config_dict['InstallFileName'] = CyberGate.xor(fields[26])
        config_dict['ActiveXStartup'] = CyberGate.xor(fields[27])
        config_dict['REGKeyHKLM'] = CyberGate.xor(fields[28])
        config_dict['REGKeyHKCU'] = CyberGate.xor(fields[29])
        config_dict['EnableMessageBox'] = CyberGate.xor(fields[30])
        config_dict['MessageBoxIcon'] = CyberGate.xor(fields[31])
        config_dict['MessageBoxButton'] = CyberGate.xor(fields[32])
        config_dict['InstallMessageTitle'] = CyberGate.xor(fields[33])
        config_dict['InstallMessageBox'] = CyberGate.xor(fields[34])
        config_dict['ActivateKeylogger'] = CyberGate.xor(fields[35])
        config_dict['KeyloggerBackspace'] = CyberGate.xor(fields[36])
        config_dict['KeyloggerEnableFTP'] = CyberGate.xor(fields[37])
        config_dict['FTPAddress'] = CyberGate.xor(fields[38])
        config_dict['FTPDirectory'] = CyberGate.xor(fields[39])
        config_dict['FTPUserName'] = CyberGate.xor(fields[41])
        config_dict['FTPPassword'] = CyberGate.xor(fields[42])
        config_dict['FTPPort'] = CyberGate.xor(fields[43])
        config_dict['FTPInterval'] = CyberGate.xor(fields[44])
        config_dict['Persistance'] = CyberGate.xor(fields[59])
        config_dict['HideFile'] = CyberGate.xor(fields[60])
        config_dict['ChangeCreationDate'] = CyberGate.xor(fields[61])
        config_dict['Mutex'] = CyberGate.xor(fields[62])
        config_dict['MeltFile'] = CyberGate.xor(fields[63])
        config_dict['CyberGateVersion'] = CyberGate.xor(fields[67])
        config_dict['StartupPolicies'] = CyberGate.xor(fields[69])
        config_dict['USBSpread'] = CyberGate.xor(fields[70])

        process_inject = CyberGate.xor(fields[57])
        if process_inject == 0 or process_inject == None:
            config_dict['ProcessInjection'] = 'Disabled'
        elif process_inject == 1:
            config_dict['ProcessInjection'] = 'Default Browser'
        elif process_inject == 2:
            config_dict['ProcessInjection'] = CyberGate.xor(fields[58])

        # Set the config to the class for use
        self.config = config_dict
