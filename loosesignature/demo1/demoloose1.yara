rule Backdoorstrings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    $a= "WS2_32.dll"
			
             $b="L$(QU"
	     
	  
			 
			 condition:
			  ($a and $b)
			 
}
