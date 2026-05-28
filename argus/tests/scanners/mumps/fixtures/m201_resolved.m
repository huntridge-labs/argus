M201CLN ; M201 clean fixture: every DO target is declared
 ;
 ; Every D / G target resolves to a label declared in this file.
 ; M201 must NOT fire.
 D STEP1
 D STEP2
 Q
STEP1
 W "step 1",!
 Q
STEP2
 W "step 2",!
 Q
