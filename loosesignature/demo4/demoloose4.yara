rule Backdoorloosedemo4strings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		     
			   $a= "ShellExecute"
					 
              $b= "kwur9*-qus/achfs,`lo.hs(vyv"
			 
			 
			 condition:
			  ($a and $b)
			 
} 





