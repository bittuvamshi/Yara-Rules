rule Backdoorloosedemo4strings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		     
			   $a=  "=#=/=4=>=G=Q=_=i=v="
			    $b= "<!<-<6<H<M<T<[<c<m<"     
					 
              
			 
			 
			 condition:
			  ($a and $b)
			 
} 






