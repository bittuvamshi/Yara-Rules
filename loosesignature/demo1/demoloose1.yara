rule Backdoorstrings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    
		    $a= "%s %s HTTP/1.0\r\n%s%s%sContent-length: %u\r\nContent-type: %s\r\n%s\r\n"
		    $b= "WS2_32.dll"
			
                    $b="L$(QU"
	     
	  
			 
			 condition:
			  ($a and $b and $c)
			 
}
