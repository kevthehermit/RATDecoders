rule RedLine
{
meta:
	description = "Identifies RedLine stealer."
	author = "@bartblaze"
	date = "2021-06"
	tlp = "White"

strings:
	$ = "Account" ascii wide
	$ = "AllWalletsRule" ascii wide
	$ = "ArmoryRule" ascii wide
	$ = "AtomicRule" ascii wide
	$ = "Autofill" ascii wide
	$ = "BrowserExtensionsRule" ascii wide
	$ = "BrowserVersion" ascii wide
	$ = "Chrome" ascii wide
	$ = "CoinomiRule" ascii wide
	$ = "CommandLineUpdate" ascii wide
	$ = "CryptoHelper" ascii wide
	$ = "CryptoProvider" ascii wide
	$ = "DataBaseConnection" ascii wide
	$ = "DesktopMessangerRule" ascii wide
	$ = "DiscordRule" ascii wide
	$ = "DisplayHelper" ascii wide
	$ = "DownloadAndExecuteUpdate" ascii wide
	$ = "DownloadUpdate" ascii wide
	$ = "ElectrumRule" ascii wide
	$ = "EndpointConnection" ascii wide
	$ = "EthRule" ascii wide
	$ = "ExodusRule" ascii wide
	$ = "Extensions" ascii wide
	$ = "FileCopier" ascii wide
	$ = "FileScanner" ascii wide
	$ = "FileScannerArg" ascii wide
	$ = "FileScannerRule" ascii wide
	$ = "FileZilla" ascii wide
	$ = "GameLauncherRule" ascii wide
	$ = "Gecko" ascii wide
	$ = "GeoHelper" ascii wide
	$ = "GeoInfo" ascii wide
	$ = "GeoPlugin" ascii wide
	$ = "GuardaRule" ascii wide
	$ = "HardwareType" ascii wide
	$ = "IpSb" ascii wide
	$ = "IRemoteEndpoint" ascii wide
	$ = "ITaskProcessor" ascii wide
	$ = "JaxxRule" ascii wide
	$ = "NordApp" ascii wide
	$ = "OpenUpdate" ascii wide
	$ = "OpenVPNRule" ascii wide
	$ = "OsCrypt" ascii wide
	$ = "Program" ascii wide
	$ = "ProgramMain" ascii wide
	$ = "ProtonVPNRule" ascii wide
	$ = "RecordHeaderField" ascii wide
	$ = "RecoursiveFileGrabber" ascii wide
	$ = "ResultFactory" ascii wide
	$ = "ScanDetails" ascii wide
	$ = "ScannedBrowser" ascii wide
	$ = "ScannedCookie" ascii wide
	$ = "ScannedFile" ascii wide
	$ = "ScanningArgs" ascii wide
	$ = "ScanResult" ascii wide
	$ = "SqliteMasterEntry" ascii wide
	$ = "StringDecrypt" ascii wide
	$ = "SystemHardware" ascii wide
	$ = "SystemInfoHelper" ascii wide
	$ = "TableEntry" ascii wide
	$ = "TaskResolver" ascii wide
	$ = "UpdateAction" ascii wide
	$ = "UpdateTask" ascii wide
	$ = "XMRRule" ascii wide

condition:
	45 of them
}
