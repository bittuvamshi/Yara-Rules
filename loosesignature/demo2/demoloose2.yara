rule Backdoorloosedemo2strings
{
    meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
    strings:
	         $a= "www.1535ss.com:8080"
            
	          $b= "WinHvqf32.exe" 
			 
	       	  $c= "??2@YAPAXI@Z"
			 
     condition:
			  ($a and $b and $c)
			 
}
