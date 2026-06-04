M001LIT ; M001 clean: pure-literal XECUTE even with a tainted var in scope
 ;
 ; X is READ-tainted, but the XECUTE argument is a constant string with
 ; nothing interpolated. M001 must NOT fire (the literal sits in source,
 ; the attacker controls nothing). Exercises the literal-descent fix.
 R X
 X "WRITE 1"
 Q
