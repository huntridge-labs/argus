M002CON ; M002 fixture: expression indirection of a NON-tainted constant
 ;
 ; CMD is a source-constant, not externally controlled. Taint-gated M002
 ; must NOT fire by default; it surfaces only at INFO when
 ; scanners.mumps.flag_generic_indirection is enabled.
 S CMD="1+1"
 S Y=@(CMD)
 Q
