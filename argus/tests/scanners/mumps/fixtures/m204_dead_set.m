M204DSET ; M204 fixture: variable set but never read
 ;
 ; LEFTOVER is assigned then never consumed; likely dead code or
 ; a leftover from a removed feature. M204 must fire on the SET.
 S USED="alive"
 S LEFTOVER="dead"
 W USED,!
 Q
