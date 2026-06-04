M204PCT ; M204 clean: %-prefixed local is read, must not be "unused"
 ;
 ; %X is NEWed, SET, then WRITTEN. The use is real; the old
 ; word-boundary backstop could not see a leading ``%`` and falsely
 ; flagged it. M204 must NOT fire on %X.
 N %X
 S %X=42
 W %X,!
 Q
