M102ARG ; M102: argument-bearing breaks are NOT unconditional exits
 ;
 ; Q X returns the value of X (the grammar splits the argument X — itself
 ; the command letter for XECUTE — into a phantom sibling). H .05 is HANG
 ; (a timed pause), not HALT. Neither makes following code unreachable, so
 ; M102 must NOT fire anywhere in this routine.
GETVAL(X) ; quit returning a value
 Q X
HANGER ; hang with an argument, then a conditional quit
 S TOTALWAIT=0
 F  H .05 Q:TOTALWAIT>3  S TOTALWAIT=TOTALWAIT+1
 Q
