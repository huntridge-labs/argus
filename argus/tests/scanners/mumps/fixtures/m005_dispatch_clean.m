M005CLN ; M005 clean fixture: DO calls a hardcoded label
 ;
 ; No tainted routine name reaches DO; the dispatch is static. M005
 ; must NOT fire.
 D HANDLER
 Q
HANDLER
 W "static dispatch only",!
 Q
