from malwareconfig import fileparser
from malwareconfig.modules import  __preprocessors__

def test_preproc_import():
    assert 'UPX' in __preprocessors__.keys()

def test_upx():
    sample_path = 'tests/samples/upx'
    file_info = fileparser.FileParser(file_path=sample_path)
    module = __preprocessors__['UPX']['obj']()
    module.set_file(file_info)
    module.pre_process()
    assert file_info.malware_name != 'UPX'