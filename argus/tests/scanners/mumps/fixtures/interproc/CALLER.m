CALLER ; inter-procedural fixture: invokes TAINTED via D ^TAINTED
 ;
 ; CALLER does no XECUTE itself. The injection happens in TAINTED.
 ; The call graph must record CALLER -> TAINTED so M001 findings on
 ; TAINTED carry CALLER in their ``inter_procedural_callers`` metadata.
 D ^TAINTED
 Q
