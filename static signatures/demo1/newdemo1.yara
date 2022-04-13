import "hash"

rule BackdoorStatic 

 {
 
    meta:
	
	    desription = "this rule is to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "041a28eda8a0b003ac54df9ef74d0069"
 
 }