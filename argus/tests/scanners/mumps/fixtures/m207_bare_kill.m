M207BK ; M207 fixture: bare KILL command
 ;
 ; The first K is unqualified — it deletes every local variable in
 ; this scope. M207 must fire on that line.
 S X=1
 S Y=2
 K
 W X,Y,!
 Q
