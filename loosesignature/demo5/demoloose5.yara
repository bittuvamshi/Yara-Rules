rule Backdoorloosedemo5strings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    $a=  "wtypesbase.h"
			
             $b=   ".refptr.WSAID_CONNECTEX__YmR9c9crObjjK9ckt1ygsPQKg"           
			 $c=  "@tableimpl.nim(118, 10) `isPowerOfTwo(initialSize)` "
			 
			 condition:
			  ($a and $b and $c)
			 
}