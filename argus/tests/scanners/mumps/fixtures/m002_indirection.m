M002IND ; M002 fixture: indirection of a READ-tainted variable
 ;
 ; CMD is read from the terminal, then ``@CMD`` evaluates its runtime
 ; value as MUMPS code. M002 (taint-gated) must fire HIGH on @CMD.
 R CMD
 X @CMD
 Q
