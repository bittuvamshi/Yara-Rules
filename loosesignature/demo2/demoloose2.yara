rule Backdoorloosedemo2strings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    $a= "Len < SrcMz->e_lfanew + (long)sizeof(IMAGE_NT_HEADERS)"
			
             $b= "??2@YAPAXI@Z"             
			 $c= "= @@" 
			 
			 condition:
			  ($a and $b and $c)
			 
}
