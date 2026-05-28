M002IND ; M002 fixture: indirection of a variable
 ;
 ; ``@CMD`` evaluates the runtime value of CMD as MUMPS code.
 ; M002 must fire on the ``@CMD`` site.
 S CMD="WRITE ""dynamic"""
 X @CMD
 Q
