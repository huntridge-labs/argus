GUARDX ; flow-sensitive sanitizer: a guard on one entry does not clean another
 ;
 ; SAVE validates RTN with a charset pattern before its dispatch, so that
 ; dispatch is sanitized. GETIT does NOT validate RTN, so its dispatch must
 ; still fire — the guard does not reach across the label boundary.
SAVE ;
 R RTN
 I RTN'?1A.7AN Q
 D @RTN
 Q
GETIT ;
 R RTN
 D @RTN
 Q
