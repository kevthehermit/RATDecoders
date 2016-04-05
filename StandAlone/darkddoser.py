# Author: Jason Jones
########################################################################
# Copyright 2014
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
########################################################################

import argparse
import os
import string
import pefile

def decrypt_str(encrypted_str,key_str):
    d = 0
    decrypted = ''
    for e in encrypted_str:
        for c in key_str:
            d = (ord(c)+d) ^ 9
        decrypted += chr(((d>>3) ^ ord(e)) % 256)
    return decrypted

def load_rsrc(pe):
    strs = {}
    rcd = pefile.RESOURCE_TYPE['RT_RCDATA']
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == rcd:
            for e in entry.directory.entries:
                data_rva = e.directory.entries[0].data.struct.OffsetToData
                size = e.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                strs[str(e.name)] = data                
            break
    return strs

def extract(filename,rsrc_name,key):
    decrypted = []
    try:
        pe = pefile.PE(filename)
        rsrc = load_rsrc(pe)
        if rsrc.get(rsrc_name,''):
            crypted_config = rsrc[rsrc_name]
            if crypted_config.find('[{#}]') != -1:
                for crypt_str in crypted_config.split('[{#}]'):
                    crypt_str = ''.join([chr(ord(c)^0xbc) for c in crypt_str])
                    decrypted.append(decrypt_str(crypt_str,key))
    except Exception, e:
        print '[+] %s: %s' % (Exception, e)
    if decrypted:
        try:
            int(decrypted[1]) # easiest way to test success, port = int
            print '[+] Filename: %s' % filename
            print '[+] CnC: %s:%s' % (decrypted[0],decrypted[1])
            print '[+] Server: %s' % decrypted[2]
            print '[+] Version: %s' % decrypted[8]
            print '[+] Mutex: %s' % decrypted[4]
            print '[+] Install: %s' % decrypted[7]
            print '[+] Service Name: %s' % decrypted[6]
            print
        except:
            print '[+] Filename: %s' % filename
            print '[+] Did not successfully decrypt config'
    else:
        print '[+] Could not locate encrypted config'

def main():
    parser = argparse.ArgumentParser(description='Extract configuration data from DarkDDoser')
    parser.add_argument('filenames',nargs='+',help='Executables to extract configuration from')
    parser.add_argument('--resource',default='BUBZ',help='Custom resource string name where encrypted config is kept')
    parser.add_argument('--key',default='darkddoser',help='Custom encryption key for encrypted config')
    args = parser.parse_args()

    if args.filenames:
        for filename in args.filenames:
            extract(filename,args.resource,args.key)
    else:
        print args.usage()

if __name__ == "__main__":
    main()
