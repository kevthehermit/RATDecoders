RATDecoders
===========

This Repo will hold a collection of Python Scripts that will extract and decode the configuration settings from common rats.

Each of these decoders is running on http://malwareconfig.com and has additional features that are not included in the scripts.

If you wish to contribute please feel free to fork or email me on decoders@malwareconfig.com

The write-up is here http://techanarchy.net/2014/04/rat-decoders/

![alt text](https://codecov.io/gh/kevthehermit/RATDecoders/branch/library/graph/badge.svg "Coverage")

## Installation

#### Requirements

There are some pre-reqs that are included in the pip setup and the requirements.txt

- pefile
- pbkdf2
- javaobj-py3
- pycrypto

For all the decoders you will need yara and yara-python. For dealing with .NET malware you will need to install yara-python with dotnet support

###### yara-python with dotnet support

git clone --recursive https://github.com/VirusTotal/yara-python
python3 setup.py build --enable-magic --enable-dotnet
sudo python3 setup.py install

#### Install from pip

pip3 install --upgrade malwareconfig

#### Install from repo

git clone git@github.com:kevthehermit/RATDecoders.git
cd RATDecoders
pip3 install -r requirements.txt
python3 setup.py install


###Current Rats
Here is a list of the currently supported RATS:

- Adwind
- Albertino Advanced RAT
- Arcom
- BlackNix
- BlackShades
- Blue Banana
- Bozok
- ClientMesh
- CyberGate
- DarkComet
- drakddoser
- DarkRat
- Graeme
- HawkEye
- jRat
- jSpy
- LostDoor
- LuxNet
- njRat
- Pandora
- PoisionIvy
- PredatorPain
- Punisher
- SpyGate
- SmallNet
- Unrecom
- Vantom
- Vertex
- VirusRat
- Xena
- xtreme

###Upcoming RATS

- NetWire
- Gh0st
- Plasma
- Any Other Rats i can find.

###Usage

The decoders now act like a framework with auto family detection. You can still find the original individual decoders in the archive folder. These will not be 
kept as up to date as the decoders in the framework. 

```malconf.py```

```malconf.py -l``` This will list all the supported rats

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

Fireye for their Poison Ivy and Xtreme rat WriteUps (Even though they ignored my tweet and reply ) - http://www.fireeye.com/blog/technical/2014/02/xtremerat-nuisance-or-threat.html

Shawn Denbow and Jesse Herts for their paper here - http://www.matasano.com/research/PEST-CONTROL.pdf Saved me a lot of time 
