rule Backdoorstrings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    
		    $a= "SYSTEM\CurrentControlSet\Services\RemoteAccess\RouterManagers\Ip"
		    $b= "WS2_32.dll"
			
                    $b="%SystemRoot%\System32\svchost.exe -k imgsvc"
	     
	  
			 
			 condition:
			  ($a and $b and $c)
			 
}
