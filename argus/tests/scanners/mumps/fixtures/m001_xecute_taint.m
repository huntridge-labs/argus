M001TNT ; M001 fixture: READ-tainted variable reaches XECUTE
 ;
 ; Demonstrates the canonical XECUTE-injection pattern.
 ; ``CMD`` is populated from a terminal READ then executed.
 W "MUMPS shell> "
 R CMD
 X CMD
 Q
