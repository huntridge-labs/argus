CALLER ; M209 fixture: passes too many args to one callee, correct to another
 ;
 ; RUN^CALLEE declares 2 formals; this call passes 3 — M209 must fire
 ; here. OK^CALLEE also declares 2 and gets 2 — must NOT fire.
 D RUN^CALLEE(1,2,3)
 D OK^CALLEE(1,2)
 Q
