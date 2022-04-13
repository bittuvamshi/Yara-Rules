rule Backdoorloosedemo4strings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		     
			   $a=  "%SystemRoot%\System32\svchost.exe -k imgsvc"
			         
					 
              
			 
			 
			 condition:
			  ($a and $b)
			 
} 






