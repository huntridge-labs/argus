M002IND ; M002 fixture: expression indirection of a READ-tainted variable
 ;
 ; CMD is read from the terminal, then @(CMD) evaluates its runtime value
 ; as a MUMPS expression in a value position — an attacker-controlled CMD
 ; like "$$EVIL^X()" is executed. M002 (taint-gated, position-aware) must
 ; fire HIGH on the @(CMD) expression indirection.
 R CMD
 S Y=@(CMD)
 Q
