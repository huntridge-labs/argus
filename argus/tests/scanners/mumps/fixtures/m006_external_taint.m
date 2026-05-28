M006EXT ; M006 fixture: tainted argument to $&CALLOUT external call
 ;
 ; READ-tainted variable flows into $&SYSTEM(). The external helper
 ; may exec a shell command using the runtime value. M006 must fire.
 R CMD
 D $&SYSTEM(CMD)
 Q
