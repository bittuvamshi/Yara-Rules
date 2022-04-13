rule Backdoorstrings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    
		     $a= "RegDeleteKey"
		    $b= "WS2_32.dll"
			
              
	     
	  
			 
			 condition:
			  ($a and $b)
			 
}
