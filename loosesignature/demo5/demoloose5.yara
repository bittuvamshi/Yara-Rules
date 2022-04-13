rule Backdoorloosedemo5strings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    $a=  "wtypesbase.h"
			
             $b=   ".refptr.WSAID_CONNECTEX__YmR9c9crObjjK9ckt1ygsPQKg"           
			 $c=  "listen__VTYZW8ymcSe8kkgeKu8O5g"
			 
			 condition:
			  ($a and $b and $c)
			 
}
