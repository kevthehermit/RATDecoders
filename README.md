RATDecoders
===========

This Repo will hold a collection of Python Scripts that will extract and decode the configuration settings from common rats.

Each of these decoders is running on http://malwareconfig.com and has additional features that are not included in the scripts.

If you wish to contribute please feel free to fork or email me on decoders@malwareconfig.com

The write-up is here http://techanarchy.net/2014/04/rat-decoders/

###Current Rats
Here is a list of the currently supported RATS:

- Adwind
- Adzok
- Albertino Advanced RAT
- AlienSpy
- Arcom
- BlackNix
- BlackShades
- Blue Banana
- Bozok
- ClientMesh
- Crimson
- CyberGate
- DarkComet
- darkddoser
- DarkRat
- Gh0st
- Graeme
- HawkEye
- JavaDropper
- jRat
- jSpy
- LostDoor
- LuxNet
- NanoCore
- njRat
- Pandora
- PoisionIvy
- PredatorPain
- Punisher
- QRat
- Sakula
- ShadowTech
- SmallNet
- SpyGate
- Tapaoux
- Unrecom
- Vantom
- Vertex
- VirusRat
- Xena
- xRat
- xtreme

###Upcoming RATS

- NetWire
- Plasma
- Any Other Rats i can find.

###Usage

The decoders now act like a framework with auto family detection. You can still find the original individual decoders in the archive folder. These will not be 
kept as up to date as the decoders in the framework. 

```python ratdecoder.py```

```python ratdecoder.py -l``` This will list all the supported rats

###Requirements

There are several modules that are required and each script is different, Please check the individual scripts. 
This list is a complete listing of all the Python Modules

- pefile
- pycrypto
- pype32
- Yara
- pbkdf2

### ToDo

There will be more decoders coming
Finish the Recursive mode on several of the Decoders

### Thanks

Full credit where credit is due. 

Malware.lu for the initial xtreme Rat Writeup - https://code.google.com/p/malware-lu/wiki/en_xtreme_RAT

Fireye for their Poison Ivy and Xtreme rat WriteUps (Even though they ignored my tweet and reply ) - http://www.fireeye.com/blog/technical/2014/02/xtremerat-nuisance-or-threat.html

Shawn Denbow and Jesse Herts for their paper here - http://www.matasano.com/research/PEST-CONTROL.pdf Saved me a lot of time 
