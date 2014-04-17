RATDecoders
===========

This Repo will hold a collection of Python Scripts that will extract and decode the configuration settings from common rats.

Each of these decoders is running on http://malwareconfig.com and has additional features that are not included in the scripts.

If you wish to contribute please feel free to fork or email me on decoders@malwareconfig.com

The write-up is here http://techanarchy.net/2014/04/rat-decoders/

###Current Rats
Here is a list of the currently supported RATS:

- Adwind
- Arcom
- BlackNix
- Blue Banana
- Bozok
- CyberGate
- DarkComet
- DarkRat
- Graeme
- jRat
- LostDoor
- njRat
- Pandora
- Punisher
- SpyGate
- SmallNet
- Vertex
- VirusRat
- xtreme

###Upcoming RATS

- BlackShades
- NetWire
- Gh0st
- Plasma
- Any Other Rats i can find.

###Usage

- Each Script comes with its own -h option use it :)

###Requirements

There are several modules that are required and each script is different, Please check the individual scripts. 
This list is a complete listing of all the Python Modules

- pefile
- pycrypto
- pype32

### ToDo

There will be more decoders coming
Finish the Recursive mode on several of the Decoders

### Thanks

Full credit where credit is due. 

Malware.lu for the initial xtreme Rat Writeup - https://code.google.com/p/malware-lu/wiki/en_xtreme_RAT

Fireye for their Poison Ivy and Xtreme rat WriteUps (Even though they ignored my tweet and reply ) - http://www.fireeye.com/blog/technical/2014/02/xtremerat-nuisance-or-threat.html

Shawn Denbow and Jesse Herts for their paper here - http://www.matasano.com/research/PEST-CONTROL.pdf Saved me a lot of time 
