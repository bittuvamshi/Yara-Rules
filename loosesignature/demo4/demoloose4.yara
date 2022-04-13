rule Backdoorloosedemo4strings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		     
			   $a=  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET4.0C; .NET4.0E)"
			         
					 
              
			 
			 
			 condition:
			  ($a and $b)
			 
} 






