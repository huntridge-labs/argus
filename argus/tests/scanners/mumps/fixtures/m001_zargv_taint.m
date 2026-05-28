M001ZAR ; M001 fixture: $ZARGV-tainted variable reaches XECUTE
 ;
 ; Process arguments (YottaDB / GT.M ``$ZARGV``) are external input;
 ; assigning them into a local variable taints it, and that variable
 ; in an XECUTE is RCE. M001 must fire.
 S CMD=$ZARGV(1)
 X CMD
 Q
