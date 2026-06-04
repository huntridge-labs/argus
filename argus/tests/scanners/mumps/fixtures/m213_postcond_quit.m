M213OK ; M213 clean fixture: legal loop breaks
 ;
 ; ``Q:I=5`` is a postconditional break (no argument); the trailing
 ; argumentless ``Q`` ends the routine. M213 must NOT fire.
 F I=1:1:10 Q:I=5  W I,!
 Q
