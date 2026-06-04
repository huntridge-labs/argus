M215Z ; M215 fixture: non-portable Z-commands vs a standard command
 ;
 ; ZSYSTEM and ZGOTO are implementation-specific; the W is portable.
 ; M215 must fire on the two Z-commands only.
 ZSYSTEM "ls"
 ZGOTO LBL
 W "portable",!
 Q
LBL ;
 Q
