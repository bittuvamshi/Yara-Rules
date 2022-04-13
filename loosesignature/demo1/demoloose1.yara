rule Backdoorstrings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    $a= "WS2_32.dll"
			
             $b="L$(QU"
	     
	     $c="WSOCK32.dll"
             
			 
			 condition:
			  ($a and $b and $c)
			 
}
