# Just a simple compile 
import yara

def test_yara_pe():
    yara.compile(source='import "pe" rule a { condition: false }')

def test_yara_dotnet():
    yara.compile(source='import "dotnet" rule a { condition: false }')

def test_yara_compile():
    pass



