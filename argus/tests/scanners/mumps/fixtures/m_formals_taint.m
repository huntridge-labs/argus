FORMALS ; formal-parameter taint (attack-surface audit mode)
 ;
 ; FILE is a formal parameter. By default it is not a taint source, so the
 ; $ZF shell call is not flagged (its origin is in a caller). With
 ; taint_sources.formals_untrusted it is treated as an untrusted boundary
 ; input and the shell injection fires.
DEL(FILE) ;
 S CMD="rm "_FILE
 S RC=$ZF(-1,CMD)
 Q
