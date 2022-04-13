rule Backdoorstrings
{
         meta: 
		     owner="vamshi"
		     malware="backdoor sample"
		   
      strings:
		    
		    $a="ShellExecute"
		     
                    $b= "RegDeleteKey"
		   
		     $c= "WS2_32.dll"
		 		 
    condition:
		
		($a and $b and $c)
						 
}
