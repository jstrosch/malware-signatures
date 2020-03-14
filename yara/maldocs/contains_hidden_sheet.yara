rule Contains_Hidden_Sheet
{
    meta:
        author = "Josh Stroschein (https://0xevilc0de.com)"
        description = "Detects a hidden or very hidden sheet in an Excel doc"
        method = "Identifies hidden sheet based off of boundsheet header"
    strings:
        $a = {85 00 ?? 00 ?? ?? (02 | 01) 00} 
    condition:
        $a
}