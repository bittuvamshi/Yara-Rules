rule Backdoorstrings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    
		    $a= "SYSTEM\CurrentControlSet\Services\RemoteAccess\RouterManagers\Ip"
		    $b= "WS2_32.dll"
			
              
	     
	  
			 
			 condition:
			  ($a and $b)
			 
}
