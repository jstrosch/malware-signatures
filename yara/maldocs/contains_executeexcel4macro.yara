rule contains_ExecuteExcel4Macro
{
   meta:
      description = "Detects the use of ExecuteExcel4Macro"
      author = "Josh Stroschein @jstrosch"
      reference = "https://twitter.com/jstrosch/status/1243191352516579328"
      date = "2020-03-26"
   
   strings:
      $a = "ExecuteExcel4Macro" ascii
   
   condition:
      $a
}