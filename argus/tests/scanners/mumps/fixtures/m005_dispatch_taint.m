M005DSP ; M005 fixture: READ-tainted variable drives dynamic DO dispatch
 ;
 ; ``RTN`` is populated from a terminal READ then used as the routine
 ; name that DO invokes via indirection. The attacker chooses which
 ; routine runs. M005 must fire on the DO site at CRITICAL severity.
 W "Which routine? "
 R RTN
 D @RTN
 Q
