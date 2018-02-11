rule TrickBot
{
strings:
$ua1 = "TrickLoader" ascii wide
$ua2 = "TrickBot" ascii wide
$ua3 = "BotLoader" ascii wide
$str1 = "<moduleconfig>*</moduleconfig>" ascii wide
$str2 = "group_tag" ascii wide
$str3 = "client_id" ascii wide
condition:
any of ($ua*) or all of ($str*)
}
