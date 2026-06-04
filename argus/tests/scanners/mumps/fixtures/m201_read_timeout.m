M201RT ; M201 clean: read-timeout must not look like an undeclared label
 ;
 ; ``R X:DTIME`` (read X with a DTIME-second timeout) is misparsed by
 ; the grammar into ``R X`` + ERROR(':') + a spurious do_statement
 ; ``DTIME`` -> routine_call ``TIME``. M201 must NOT flag ``TIME`` as
 ; an undeclared label (ERROR-sibling + command-mnemonic guards).
 R X:DTIME
 W X,!
 Q
