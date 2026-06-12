M005LIT ; M005: dispatch to fixed string-literal targets is not injection
 ;
 ; TYPE is READ-tainted, but @$S(...) selects between two HARDCODED routine
 ; names — the user can only choose which fixed routine runs, not inject an
 ; arbitrary one. M005 must NOT fire (a direct D @TYPE still would).
EN ;
 R TYPE
 D @$S(TYPE="B":"PRINT2",1:"PRINT")
 Q
PRINT ;
 Q
PRINT2 ;
 Q
