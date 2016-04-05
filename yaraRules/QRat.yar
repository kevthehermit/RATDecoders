rule QRat
{
    meta:
        author = "Kevin Breen @KevTheHermit"
        date = "2015/08"
        ref = "http://malwareconfig.com"
        maltype = "Remote Access Trojan"
        filetype = "jar"
        
    strings:
        $a0 = "e-data"
        $a1 = "quaverse/crypter"
        $a2 = "Qrypt.class"
        $a3 = "Jarizer.class"
        $a4 = "URLConnection.class"
        
        
    condition:
        4 of them


}