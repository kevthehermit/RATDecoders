import os
from malwareconfig import fileparser
from malwareconfig.modules import __decoders__

def test_decoders_import():
    assert 'AAR' in __decoders__.keys()
    assert 'AdWind' in __decoders__.keys()
    assert 'Adzok' in __decoders__.keys()
    assert 'AlienSpy' in __decoders__.keys()
    assert 'Alina' in __decoders__.keys()
    assert 'Arcom' in __decoders__.keys()
    assert 'BlackNix' in __decoders__.keys()
    assert 'BlackShades' in __decoders__.keys()
    assert 'BlueBanana' in __decoders__.keys()
    assert 'Bozok' in __decoders__.keys()
    assert 'ClientMesh' in __decoders__.keys()
    assert 'CyberGate' in __decoders__.keys()
    assert 'DarkComet' in __decoders__.keys()
    assert 'HawkEye' in __decoders__.keys()
    assert 'Jbifrost' in __decoders__.keys()
    assert 'JRat' in __decoders__.keys()
    assert 'LostDoor' in __decoders__.keys()
    assert 'LuminosityLink' in __decoders__.keys()
    assert 'NanoCore' in __decoders__.keys()
    assert 'njRat' in __decoders__.keys()
    assert 'Sakula' in __decoders__.keys()
    assert 'Xtreme' in __decoders__.keys()


def decode_sample(sample_path):
    file_info = fileparser.FileParser(file_path=sample_path)
    if file_info.malware_name in __decoders__:
        module = __decoders__[file_info.malware_name]['obj']()
        module.set_file(file_info)
        module.get_config()
        conf = module.config
        return conf

def test_aar():
    sample_path = "tests/samples/aar"
    results = decode_sample(sample_path)
    assert results['Version'] == '4.x'

def test_adwind():
    sample_path = "tests/samples/adwind"
    results = decode_sample(sample_path)
    assert results['Version'] == 'Adwind RAT v2.0'

def test_adzok():
    sample_path = "tests/samples/adzok"
    results = decode_sample(sample_path)
    assert results['Registry Key'] == 'Winhttpsvc'

def test_alienspy():
    sample_path = "tests/samples/alienspy"
    results = decode_sample(sample_path)
    assert results['pluginfoldername'] == 'ryfne6pMMZ'

#def test_alina():
#    sample_path = "tests/samples/alina"
#    results = decode_sample(sample_path)
#    assert results['pluginfoldername'] == 'ryfne6pMMZ'

def test_arcom():
    sample_path = "tests/samples/arcom"
    results = decode_sample(sample_path)
    assert results['Install Name'] == 'vlc.exe'

def test_blackshades():
    sample_path = "tests/samples/blackshades"
    results = decode_sample(sample_path)
    assert results['Client Control Port'] == '5555'

def test_bluebanana():
    sample_path = "tests/samples/bluebanana"
    results = decode_sample(sample_path)
    assert results['Password'] == '1111'

def test_blacknix():
    sample_path = "tests/samples/arcom"
    results = decode_sample(sample_path)
    assert results['Install Name'] == 'vlc.exe'

def test_bozok():
    sample_path = "tests/samples/bozok"
    results = decode_sample(sample_path)
    assert results['InstallName'] == 'wmiserver.exe'

def test_clientmesh():
    sample_path = "tests/samples/clientmesh"
    results = decode_sample(sample_path)
    assert results['RegistryKey'] == 'Windows Def'

def test_cybergate():
    sample_path = "tests/samples/cybergate"
    results = decode_sample(sample_path)
    assert results['CampaignID'] == 'cyber'

def test_darkcomet():
    sample_path = "tests/samples/darkcomet"
    results = decode_sample(sample_path)
    assert results['MUTEX'] == 'DC_MUTEX-SEJ8D2Y'

def test_darkrat():
    sample_path = "tests/samples/darkrat"
    results = decode_sample(sample_path)
    assert results['Timer Interval'] == b'1000'

def test_hawkeye():
    sample_path = "tests/samples/hawkeye"
    results = decode_sample(sample_path)
    assert results['Key6'] == '587'

def test_hworm():
    sample_path = "tests/samples/hworm/wsh-vbs"
    results = decode_sample(sample_path)
    assert results['host'] == 'domainname.com'

#def test_jbifrost():
#    sample_path = "tests/samples/jbifrost"
#    results = decode_sample(sample_path)
#    assert results['Key6'] == '587'


def test_jrat():
    sample_path = "tests/samples/jrat1"
    results = decode_sample(sample_path)
    assert results['Persistance'] == 'false'


def test_lostdoor():
    sample_path = "tests/samples/lostdoor"
    results = decode_sample(sample_path)
    assert results['Campaign'] == 'My Host'

def test_luminositylink():
    sample_path = "tests/samples/luminositylink"
    results = decode_sample(sample_path)
    assert results['Install Name'] == 'sysmon.exe'

def test_luxnet():
    sample_path = "tests/samples/luxnet"
    results = decode_sample(sample_path)
    assert results['domain'] == '192.168.50.102'

def test_nanocore():
    nanocore_tests = {
        "1": "Group",
        "2": "Kids",
        "3": "Group"
    }
    for filename, groupname in nanocore_tests.items():
        sample_path = os.path.join("tests/samples/nanocore/", filename)
        results = decode_sample(sample_path)
        assert results['Group'].decode('utf-8') == groupname

def test_netwire():
    sample_path = "tests/samples/netwire"
    results = decode_sample(sample_path)
    assert results['Password'] == b'Password'

def test_njrat():
    njrat_tests = {
        "05e": "0.5.0e",
        "07d": "0.7d",
        "035": "0.3.5",
        "036": "0.3.6",
        "041": "0.4.1a",
        "064": "0.6.4",
        "071": "0.7.1"
    }

    for filename, version in njrat_tests.items():
        sample_path = os.path.join("tests/samples/njrat/", filename)
        results = decode_sample(sample_path)
        assert results['version'].lower() == version

def test_remcos():
    remcos_tests = {
        "111": "1.1 Free",
        "17pro": "1.7 Pro",
        "220": "2.2.0 Light",
        "250": "2.5.0 Light"
    }

    for filename, version in remcos_tests.items():
        sample_path = os.path.join("tests/samples/remcos/", filename)
        results = decode_sample(sample_path)
        assert results['version'] == version

#def test_sakula():
#    sample_path = "tests/samples/sakula"
#    results = decode_sample(sample_path)
#    print(results)
#    assert results['Install Name'] == 'Trojan.exe'

def test_saefko():
    sample_path = "tests/samples/saefko"
    results = decode_sample(sample_path)
    assert results['server_pass'] == 'toor'

def test_spynote():
    spynote_tests = {
        "spynote5": "5.0",
        "spynote6.4": "2.1.2.79"
    }

    for filename, version in spynote_tests.items():
        sample_path = os.path.join("tests/samples/spynote/", filename)
        results = decode_sample(sample_path)
        assert results['Version'] == version

def test_xtreme():
    sample_path = "tests/samples/xtreme"
    results = decode_sample(sample_path)
    assert results['ID'] == 'hack'