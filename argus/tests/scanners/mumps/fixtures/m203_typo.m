M203TYPO ; M203 fixture: variable read without prior definition (typo)
 ;
 ; The developer SET USER but the W references USR — classic typo.
 ; MUMPS treats USR as the empty string and the bug is silent at
 ; runtime. M203 must fire on USR.
 S USER="alice"
 W USR,!
 Q
