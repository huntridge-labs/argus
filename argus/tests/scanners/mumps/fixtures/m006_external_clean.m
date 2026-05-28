M006CLN ; M006 clean fixture: $& call with no tainted argument
 ;
 ; $&PURE() takes only a constant — no tainted variable reaches it.
 ; M006 must NOT fire.
 D $&PURE("hello")
 Q
