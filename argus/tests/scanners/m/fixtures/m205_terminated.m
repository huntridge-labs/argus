M205OK ; M205 clean fixture: every label body ends with Q
 ;
 ; Each label terminates with an unconditional Q before the next
 ; label begins. No fallthrough. M205 must NOT fire.
 D STEP1
 Q
STEP1
 W "step 1",!
 Q
STEP2
 W "step 2",!
 Q
