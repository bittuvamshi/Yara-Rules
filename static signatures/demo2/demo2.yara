 import "hash"

rule BackdoorStatic 

 {
 
    meta:
	
	    desription = "this rule is to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "39f15ed00a66cc10efb238b7931ae4a8"
 
 }