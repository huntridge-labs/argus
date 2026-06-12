M001CLN ; M001 clean fixture: XECUTE of string literal only
 ;
 ; No READ-tainted variable reaches XECUTE; XECUTE is invoked with a
 ; constant string. M001 must NOT fire.
 X "WRITE ""hello, world""," ; literal, safe
 Q
