import pype32
import base64


def config(raw_data):
    try:
        pe = pype32.PE(data=raw_data)
        string_list = get_strings(pe, 2)
        config_dict = parse_config(string_list)
        if config_dict:
            return config_dict
        else:
            return False
    except Exception as e:
        return False
        
#Helper Functions Go Here

# Get a list of strings from a section
def get_strings(pe, dir_type):
    string_list = []
    m = pe.ntHeaders.optionalHeader.dataDirectory[14].info
    for s in m.netMetaDataStreams[dir_type].info:
        for offset, value in s.iteritems():
            string_list.append(value)
    return string_list
            
#Turn the strings in to a python dict
def parse_config(string_list):
    config_dict = {}
    if "|'|'|" in string_list:
        config_dict["species"] = 'njrat'
        if string_list[5] == '0.3.5':
            config_dict["Campaign ID"] = base64.b64decode(string_list[4])
            config_dict["version"] = string_list[5]
            config_dict["Install Name"] = string_list[1]
            config_dict["Install Dir"] = string_list[2]
            config_dict["Registry Value"] = string_list[3]
            config_dict["Domain"] = string_list[7]
            config_dict["Port"] = string_list[8]
            config_dict["Network Separator"] = string_list[9]
            config_dict["Install Flag"] = string_list[6]
            
        elif string_list[6] == '0.3.6':
            config_dict["Campaign ID"] = base64.b64decode(string_list[5])
            config_dict["version"] = string_list[6]
            config_dict["Install Name"] = string_list[2]
            config_dict["Install Dir"] = string_list[3]
            config_dict["Registry Value"] = string_list[4]
            config_dict["Domain"] = string_list[8]
            config_dict["Port"] = string_list[9]
            config_dict["Network Separator"] = string_list[10]
            config_dict["Install Flag"] = string_list[11]
            
        elif  string_list[3] == '0.4.1a':
            config_dict["Campaign ID"] = base64.b64decode(string_list[2])
            config_dict["version"] = string_list[3]
            config_dict["Install Name"] = string_list[5]
            config_dict["Install Dir"] = string_list[6]
            config_dict["Registry Value"] = string_list[7]
            config_dict["Domain"] = string_list[8]
            config_dict["Port"] = string_list[9]
            config_dict["Network Separator"] = string_list[10]
            config_dict["Install Flag"] = string_list[11]

            
        elif  string_list[2] == '0.5.0E':
            config_dict["Campaign ID"] = base64.b64decode(string_list[1])
            config_dict["version"] = string_list[2]
            config_dict["Install Name"] = string_list[4]
            config_dict["Install Dir"] = string_list[5]
            config_dict["Registry Value"] = string_list[6]
            config_dict["Domain"] = string_list[7]
            config_dict["Port"] = string_list[8]
            config_dict["Network Separator"] = string_list[10]
            config_dict["Install Flag"] = string_list[9]

            
        elif  string_list[2] == '0.6.4':
            config_dict["Campaign ID"] = base64.b64decode(string_list[1])
            config_dict["version"] = string_list[2]
            config_dict["Install Name"] = string_list[3]
            config_dict["Install Dir"] = string_list[4]
            config_dict["Registry Value"] = string_list[5]
            config_dict["Domain"] = string_list[6]
            config_dict["Port"] = string_list[7]
            config_dict["Network Separator"] = string_list[8]
            config_dict["Install Flag"] = string_list[9]
            
        elif string_list[2] == '0.7.1':
            config_dict["Campaign ID"] = base64.b64decode(string_list[1])
            config_dict["version"] = string_list[2]
            config_dict["Mutex"] = string_list[3]
            config_dict["Install Name"] = string_list[4]
            config_dict["Install Dir"] = string_list[5]
            config_dict["Registry Value"] = string_list[6]
            config_dict["Domain"] = string_list[7]
            config_dict["Port"] = string_list[8]
            config_dict["Network Separator"] = string_list[10]
            config_dict["Install Flag"] = string_list[9]
            config_dict["Author"] = string_list[12]
            
        elif string_list[2] == '0.7d':
            config_dict["Campaign ID"] = base64.b64decode(string_list[1])
            config_dict["version"] = string_list[2]
            config_dict["Install Name"] = string_list[3]
            config_dict["Install Dir"] = string_list[4]
            config_dict["Registry Value"] = string_list[5]
            config_dict["Domain"] = string_list[6]
            config_dict["Port"] = string_list[7]
            config_dict["Network Separator"] = string_list[8]
            config_dict["Install Flag"] = string_list[9]

        elif string_list[2] == '0.8d':
            config_dict["Campaign ID"] = base64.b64decode(string_list[1])
            config_dict["version"] = string_list[2]
            config_dict["Install Name"] = string_list[4]
            config_dict["Install Dir"] = string_list[5]
            config_dict["Registry Value"] = string_list[6]
            config_dict["Domain"] = string_list[7]
            config_dict["Port"] = string_list[8]
            config_dict["Network Separator"] = string_list[9]
            config_dict["Install Flag"] = string_list[10]

    elif "|Kiler|" in string_list:
        config_dict["species"] = 'kiler'
        if string_list[4] == '4.0.1':
            config_dict["Campaign ID"] = base64.b64decode(string_list[3])
            config_dict["version"] = string_list[4]
            config_dict["Install Name"] = string_list[6]
            config_dict["Install Dir"] = string_list[7]
            config_dict["Registry Value"] = string_list[8]
            config_dict["Domain"] = string_list[9]
            config_dict["Port"] = string_list[10]
            config_dict["Network Separator"] = string_list[13]
            config_dict["Install Flag"] = string_list[11]

        elif string_list[4] == '8.0.9': 
            config_dict["Campaign ID"] = base64.b64decode(string_list[3])
            config_dict["version"] = string_list[4]
            config_dict["Install Name"] = string_list[6]
            config_dict["Install Dir"] = string_list[7]
            config_dict["Registry Value"] = string_list[9]
            config_dict["Domain"] = string_list[10]
            config_dict["Port"] = string_list[11]
            config_dict["Network Separator"] = string_list[17]
            config_dict["Install Flag"] = string_list[13]

    elif "|Coringa|" in string_list:
        config_dict["species"] = 'coringa'
        if string_list[26] == '0.3':
            config_dict["Campaign ID"] = base64.b64decode(string_list[25])
            config_dict["version"] = string_list[26]
            config_dict["Install Name"] = string_list[28]
            config_dict["Install Dir"] = string_list[29]
            config_dict["Registry Value"] = string_list[30]
            config_dict["Domain"] = string_list[31]
            config_dict["Port"] = string_list[32]
            config_dict["Network Separator"] = string_list[48]
            config_dict["Install Flag"] = string_list[33]

    # Try a brute force
    if "|'|'|" in string_list and len(config_dict) == 0:
        offset = string_list.index("|'|'|")
        config_dict["Campaign ID"] = base64.b64decode(string_list[offset -7])
        config_dict["version"] = string_list[offset -6]
        config_dict["Install Name"] = string_list[offset -5]
        config_dict["Install Dir"] = string_list[offset -4]
        config_dict["Registry Value"] = string_list[offset -3]
        config_dict["Domain"] = string_list[offset -2]
        config_dict["Port"] = string_list[offset -1]

    if len(config_dict) > 0:
        return config_dict
