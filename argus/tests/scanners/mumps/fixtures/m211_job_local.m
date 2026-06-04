M211JOB ; M211: a scratch global subscripted by a $J-derived local is private
 ;
 ; ^TMP(JOB,...) where JOB=$J is per-process — must NOT fire.
 ; ^TMP("SHARED") with no $J subscript is a real race — must fire.
JOBPRIV ;
 S JOB=$J
 S ^TMP(JOB,"DATA")=1
 Q
SHARED ;
 S ^TMP("SHARED")=1
 Q
