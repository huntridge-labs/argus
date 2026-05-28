M203FA(A,B) ; M203 clean: formal args A,B are defined by the caller
 ;
 ; A and B are formal parameters declared in the entry-label parens.
 ; They parse as ``arguments`` siblings of the label node. M203 must
 ; NOT flag them as read-before-defined.
 S X=A+B
 W X,!
 Q
