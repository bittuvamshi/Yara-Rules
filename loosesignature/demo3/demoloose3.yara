rule Backdoorloosedemo3strings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
        strings:
		    $a= "jhjkkkkkkkkkkkkkkkkkkkkkkkkkkkk 8HCvg7MydLhdqbka7gLw165kEEhJzae1wxEFayLsKDydrhCt7eGzI6jpgGkDasG3Eu3e28Dk15tKkhrExDDypdF9IG1xmdGdrk559Acy7nxdjz8nt 9H37Defc5DKnJDallJl1vmywaBud7nediixsqBhz168sbbi3ozFiJa64LvMFrG5EuH7xK2GcgKMep46htKjczGhGLzEja8yDr4 xnEvnC5oueG44BBBFwvtpmwFALC411Hfleuy246I4E85tm4azeEk8ABEtDGmtislEsAeercdjfyADuempLAG1bKuqhehzg r6jA5CuFKb9lsDxIAABtKkq2mbJitCI49rFHKuGf2j2tpklA66oyzF2jDkdrzI AqH jpwvJGf MC4lpMd3pbplvzKBtvrsIpxtiskww vwzvq5uAsB7qq2L7zq6yssEy54IjCMFIfhen3kEBmhF9qtvx1lHvaGrAgkLkM9ndsroBlxrF4kBC3n3eHezsc6pCcoypwLMEABnBa2H751C7eqf189vIgi3kBbhC6Ak5bm8xumoDFKEF8vDAtMdK42c5FBgp  mGoE958MyBMqqiJcx1AdsH547tnbgL8jvGI7flHFwIhDqLkoK99jGxh8sKkwunnffDxefDG6g375oJ9MeH2A1IIJkygJCecg6DL41jk 2Mghoho3C6IpLBsdjkCrzBqyvH1F88qjClvLIh iMw14laGyrilIxakiKK 4uMtBFqCBmFxz585yLdvmDrCHbJ4A7FlEgjrEIm5wK2Ed941bo Id76b9fchwcoi79CKucC9bjaGGluMtJjKoeDHagqol8JDq499lx9b77st7olJKceJLm3wzdeo4fqCoEnI4t7J 5hbFJa4iuvdAtzmiudgCJJMgFi72aiL8Epkwo82 o6qLAiKckv57Cd42 2EA4Abj2kejyd4vz1x63J3rcBqCqccxcMaxv9le856uAGEmssbskfuxLL4pmbdJHr8BHrboz85gk 4qCDozMLcM6w4eod8gHcbjnGgKMM1bih3KfGtao4p2jak5jjkvkCbdaq1qyz9vH4 zobjwydqcqDgd mjs2Bxry yGa7kp6uk7Ehrhcp2wouGl cy5izH5iL2gajJoCF2g6xpMuj6LCG73cpoLCc5g2G4Izqy 8b2Ep o4fv3Hf13k26Kw99CDge8cd8sy cnEHKoi6B5 fmuLi1kjBonkvpm6BlBlrGbpJ6f638pdekClFvcynaA3eaLHjv7lMrv 3 o2z xAJcdfz7 Dhw7B66CiyfEshpv1xwkfclj8dCwrlvCAE4oqC1KMswEmrtkwE2LiGyGatGGraJddjH5wgKMcMhbfilkrohyn6BhLvfckJi79Cfvava9jgkzDhpjkiBx3edaLhBy4cfLA2zsxtBitaejIIbjjkprKKw53fzzI257vf AbCjBDw6B5f9y49gvEaF12qtji3w9gwB9ytigADg8Cv2AIzK udb1CvGrcpooumejqcwk8HljJ39BBMIbxMB8n1D7JL9LL41I85 jkgbpknjAJc3Lx47plpyyBFj17hrqpM23guMHxpKerfII2GmebK5fmigczgkB9cxhslMwjxE2ggnMw8bIhhmv7pDH njkICGKa2pux42fz5uj5aoLoiImM4w83DAz ibpnJ9Ii3EdI4zkgGq mCxeFuhr41Ap2jiG5qlG9niKH4j1 noLbqoozhKftDyLwJuy1uvbi5d5iAtyDom A6cLJoAuDu97hvCsDlkGr3Hj56zguajo8eGL8nrcADuscFjMlxH78hJenuton2apo4mMa41drFiEhmzdHojwkqsaqCk4Adw6k3jxFFKCHaH1iGw5Jsnf7joGgK3wEBmvibM7 1eEBnGDwG8K9M7mwD Lj51elEMhduu1Govc4gE9axB79Gpn5p1DhfxvoyjzbE3IiB aaaaaaaaaaaaaaaaaaaaaaaaaa"
	  		
                     $b= "jhjkkkkkkkkkkkkkkkkkkkkkkkkkkkk 8HCvg7MydLhdqbka7gLw165kEEhJzae1wxEFayLsKDydrhCt7eGzI6jpgGkDasG3Eu3e28Dk15tKkhrExDDypdF9IG1xmdGdrk559Acy7nxdjz8nt 9H37Defc5DKnJDallJl1vmywaBud7nediixsqBhz168sbbi3ozFiJa64LvMFrG5EuH7xK2GcgKMep46htKjczGhGLzEja8yDr4 xnEvnC5oueG44BBBFwvtpmwFALC411Hfleuy246I4E85tm4azeEk8ABEtDGmtislEsAeercdjfyADuempLAG1bKuqhehzg r6jA5CuFKb9lsDxIAABtKkq2mbJitCI49rFHKuGf2j2tpklA66oyzF2jDkdrzI AqH jpwvJGf MC4lpMd3pbplvzKBtvrsIpxtiskww vwzvq5uAsB7qq2L7zq6yssEy54IjCMFIfhen3kEBmhF9qtvx1lHvaGrAgkLkM9ndsroBlxrF4kBC3n3eHezsc6pCcoypwLMEABnBa2H751C7eqf189vIgi3kBbhC6Ak5bm8xumoDFKEF8vDAtMdK42c5FBgp  mGoE958MyBMqqiJcx1AdsH547tnbgL8jvGI7flHFwIhDqLkoK99jGxh8sKkwunnffDxefDG6g375oJ9MeH2A1IIJkygJCecg6DL41jk 2Mghoho3C6IpLBsdjkCrzBqyvH1F88qjClvLIh iMw14laGyrilIxakiKK 4uMtBFqCBmFxz585yLdvmDrCHbJ4A7FlEgjrEIm5wK2Ed941bo Id76b9fchwcoi79CKucC9bjaGGluMtJjKoeDHagqol8JDq499lx9b77st7olJKceJLm3wzdeo4fqCoEnI4t7J 5hbFJa4iuvdAtzmiudgCJJMgFi72aiL8Epkwo82 o6qLAiKckv57Cd42 2EA4Abj2kejyd4vz1x63J3rcBqCqccxcMaxv9le856uAGEmssbskfuxLL4pmbdJHr8BHrboz85gk 4qCDozMLcM6w4eod8gHcbjnGgKMM1bih3KfGtao4p2jak5jjkvkCbdaq1qyz9vH4 zobjwydqcqDgd mjs2Bxry yGa7kp6uk7Ehrhcp2wouGl cy5izH5iL2gajJoCF2g6xpMuj6LCG73cpoLCc5g2G4Izqy 8b2Ep o4fv3Hf13k26Kw99CDge8cd8sy cnEHKoi6B5 fmuLi1kjBonkvpm6BlBlrGbpJ6f638pdekClFvcynaA3eaLHjv7lMrv 3 o2z xAJcdfz7 Dhw7B66CiyfEshpv1xwkfclj8dCwrlvCAE4oqC1KMswEmrtkwE2LiGyGatGGraJddjH5wgKMcMhbfilkrohyn6BhLvfckJi79Cfvava9jgkzDhpjkiBx3edaLhBy4cfLA2zsxtBitaejIIbjjkprKKw53fzzI257vf AbCjBDw6B5f9y49gvEaF12qtji3w9gwB9ytigADg8Cv2AIzK udb1CvGrcpooumejqcwk8HljJ39BBMIbxMB8n1D7JL9LL41I85 jkgbpknjAJc3Lx47plpyyBFj17hrqpM23guMHxpKerfII2GmebK5fmigczgkB9cxhslMwjxE2ggnMw8bIhhmv7pDH njkICGKa2pux42fz5uj5aoLoiImM4w83DAz ibpnJ9Ii3EdI4zkgGq mCxeFuhr41Ap2jiG5qlG9niKH4j1 noLbqoozhKftDyLwJuy1uvbi5d5iAtyDom A6cLJoAuDu97hvCsDlkGr3Hj56zguajo8eGL8nrcADuscFjMlxH78hJenuton2apo4mMa41drFiEhmzdHojwkqsaqCk4Adw6k3jxFFKCHaH1iGw5Jsnf7joGgK3wEBmvibM7 1eEBnGDwG8K9M7mwD Lj51elEMhduu1Govc4gE9axB79Gpn5p1DhfxvoyjzbE3IiB aaaaaaaaaaaaaaaaaaaaaaaaaa0"           
 			 
	 		
                      $c= "soundrec.exe"
      condition:
			  ($a and $b or $c)
			 
}
