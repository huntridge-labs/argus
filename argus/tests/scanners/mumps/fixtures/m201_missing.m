M201 ; M201 fixture: DO references a label that isn't declared
 ;
 ; ``D MISSING`` has no corresponding LABEL declaration in this file.
 ; At runtime the dispatch raises an undefined-label error.
 ; M201 must fire.
 D MISSING
 D STEP1
 Q
STEP1
 W "step 1",!
 Q
