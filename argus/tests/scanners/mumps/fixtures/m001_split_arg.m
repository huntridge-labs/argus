M001SPL ; M001: command-position recovery catches a split "X B", not var-X misparses
 ;
 ; The grammar can split "X B" into [X, B]. A command-position recovery still
 ; flags it (B is READ-tainted). But a tainted variable X used as an IF
 ; operand or a QUIT value is NOT an XECUTE and must not fire.
EN ;
 R B
 X B
 R X
 I X=2 W "two"
 Q X
