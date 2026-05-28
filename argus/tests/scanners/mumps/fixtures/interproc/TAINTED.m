TAINTED ; inter-procedural fixture: READ-tainted XECUTE
 ;
 ; READ a command from the terminal, then XECUTE it — classic
 ; injection. CALLER^ invokes this routine, so M001 findings here
 ; must carry CALLER in their ``inter_procedural_callers`` metadata.
 W "MUMPS shell> "
 R CMD
 X CMD
 Q
