rule Backdoorstrings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    $a= "??3@YAXPAX@Z"
			
             $b="L$(QU"
             
			 
			 condition:
			  ($a and $b)
			 
}
