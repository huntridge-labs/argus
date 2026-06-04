M001CAT ; M001 fixture: concatenation of a literal with a tainted var
 ;
 ; The XECUTE argument is built at runtime from tainted X — real
 ; injection. M001 must fire (concatenation is NOT a pure literal).
 R X
 X "SET Y="_X
 Q
