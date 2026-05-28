M102PC ; M102 clean fixture: postconditional Q does not make following code dead
 ;
 ; ``Q:cond`` only exits when ``cond`` is true. The W after it IS
 ; reachable. M102 must NOT fire.
 S X=5
 Q:X<0
 W "still reachable",!
 Q
