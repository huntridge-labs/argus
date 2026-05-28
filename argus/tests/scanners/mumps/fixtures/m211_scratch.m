M211SC ; M211 fixture: scratch global with and without $J + a LOCK
 ;
 ; ^TMP("KEY") has no $J — cross-process collision (M211 fires).
 ; ^TMP($J,"KEY") is per-process (clean). LOCK is not a write (clean).
 S ^TMP("KEY")="bad"
 S ^TMP($J,"KEY")="good"
 L +^TMP(X)
 Q
