SANIT ; Phase A: sound sanitizers clear taint without hiding real injection
 ;
 ; Numeric coercion (+N) and a charset pattern-match guard (?1A.7AN) both
 ; constrain a value so it cannot carry shell/code metacharacters. The
 ; sanitized values reaching XECUTE / dispatch must NOT fire; the raw
 ; tainted value still must.
NUM ; numeric coercion sanitizes
 R N
 S SAFE=+N
 X SAFE
 Q
PAT ; pattern-match charset guard sanitizes the dispatch target
 R RTN
 I RTN'?1A.7AN Q
 D @RTN
 Q
RAW ; unsanitized control — must still fire
 R EVIL
 X EVIL
 Q
