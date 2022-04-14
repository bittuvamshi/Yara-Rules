rule Backdoorloosedemo5strings
{
   meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
  strings:
		    $a=  "http://serv1.ec2-102-95-13-2-ubuntu.local"
		     
		    $b=  "listen__VTYZW8ymcSe8kkgeKu8O5g"
			 
		   $c=   ".refptr.WSAID_CONNECTEX__YmR9c9crObjjK9ckt1ygsPQKg"         
			 
   condition:
			  ($a and $b and $c)
			 
}
