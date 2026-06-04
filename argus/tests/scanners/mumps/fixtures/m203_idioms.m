M203OK(ARG1,ARG2) ; formal args, FOR var, guarded reads must NOT flag
 N RESULT,I
 S RESULT=ARG1_ARG2
 F I=1:1:3 S RESULT=RESULT_$C(I)
 W:$D(MAYBE) "has it"
 W $G(PERHAPS)
 U IO:(READONLY:NOECHO)
 D SUB(.PASSED)
 Q RESULT
M203BUG ; genuine read-before-def typo MUST flag
 N USERNAME S USERNAME="alice"
 W USRNAME
 Q
SUB(X) ;
 S X=1
 Q
