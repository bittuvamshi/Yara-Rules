import "hash"

rule BackdoorStaticdemo4

 {
 
    meta:
	
	    desription = "this rule is to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "1d8562c0adcaee734d63f7baaca02f7c"
 
 }