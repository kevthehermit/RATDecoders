RATDecoders
===========

Malconf is a python3 library that can be used to staticly analyse specific malware families and extract the Configuration data that can be used by 
Incident Responders during an incident. 

As a library it can also be installed in to automated malware analysis pipelines. 


![Coverage](https://codecov.io/gh/kevthehermit/RATDecoders/branch/master/graph/badge.svg "Coverage")

[![Build Status](https://travis-ci.org/kevthehermit/RATDecoders.svg?branch=master)](https://travis-ci.org/kevthehermit/RATDecoders)


## Installation

#### Requirements

There are some pre-reqs that are included in the pip setup and the requirements.txt

- pefile
- pbkdf2
- javaobj-py3
- pycrypto
- androguard

For all the decoders you will need yara and yara-python. For dealing with .NET malware you will need to install yara-python with dotnet support

##### yara-python with dotnet support

```
git clone --recursive https://github.com/VirusTotal/yara-python
python3 setup.py build --enable-magic --enable-dotnet
sudo python3 setup.py install
```

#### Install from pip

```
pip3 install --upgrade malwareconfig
```

#### Install from repo

```
git clone git@github.com:kevthehermit/RATDecoders.git
cd RATDecoders
pip3 install -r requirements.txt
python3 setup.py install
```

### Current Rats
Here is a list of the currently supported RATS:

  - LostDoor
  - Xtreme
  - AAR
  - AdWind
  - Adzok
  - AlienSpy
  - Alina
  - Arcom
  - BlackNix
  - BlackShades
  - BlueBanana
  - Bozok
  - ClientMesh
  - CyberGate
  - DarkComet
  - DarkRAT
  - HawkEye
  - Hrat / hworm / WSH
  - Jbifrost
  - JRat
  - LuminosityLink
  - LuxNet
  - NanoCore
  - NetWire
  - njRat
  - Plasma
  - Remcos
  - Saefko
  - Sakula
  - SpyNote / Mobihook

### Upcoming RATS

- Still migrating old ones!

### Usage

Using the supplied command line tool `malconf` you can pass in a single file or a directory with the `-r` flag and it will attempt to automagically detect the family and extract any config. 

You can also use the `-o` option to write results out to a file.


```malconf```

```malconf -l``` This will list all the supported rats

```malconf /path/to/sample ``` This will automagically detect the family and run the decoder

```
⇒  malconf tests/samples/alienspy 

 __  __       _  ____             __ 
|  \/  | __ _| |/ ___|___  _ __  / _|
| |\/| |/ _` | | |   / _ \| '_ \| |_ 
| |  | | (_| | | |__| (_) | | | |  _|
|_|  |_|\__,_|_|\____\___/|_| |_|_| 

Malware Configuration Parser by @kevthehermit

[+] Loading File: tests/samples/alienspy
  [-] Found: AlienSpy
  [-] Running Decoder
  [-] Config Output

{'ConfigKey': 'fzGUoTaQH3SUW7E82IKQK2J2J2IISIS',
 'NAME': 'ok',
 'Version': 'B',
 'connetion_time': '0',
 'desktop': 'true',
 'dns': '213.208.129.211',
 'extensionname': 'qQJ',
 'folder': 'java',
 'instalar': 'true',


```

### Library

If you pip install you can also use it is a library. 

```
from malwareconfig import fileparser
from malwareconfig.modules import __decoders__, __preprocessors__

# Open and parse the file
sample_path = '/path/to/sample.exe'
file_info = fileparser.FileParser(file_path=sample_path)

# Check for a valid decoder and then parse
if file_info.malware_name in __decoders__:
    module = __decoders__[file_info.malware_name]['obj']()
    module.set_file(file_info)
    module.get_config()
    conf = module.config
    pprint(conf)

```


### Thanks

Full credit where credit is due. 

Malware.lu for the initial xtreme Rat Writeup - https://code.google.com/p/malware-lu/wiki/en_xtreme_RAT

Fireye for their Poison Ivy and Xtreme rat WriteUps (Even though they ignored my tweets :-) ) - http://www.fireeye.com/blog/technical/2014/02/xtremerat-nuisance-or-threat.html

Shawn Denbow and Jesse Herts for their paper here - http://www.matasano.com/research/PEST-CONTROL.pdf Saved me a lot of time 

