import "hash"

rule BackdoorStaticdemo5

 {
 
    meta:
	
	    desription = "this rule is to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "334a10500feb0f3444bf2e86ab2e76da"
 
 }