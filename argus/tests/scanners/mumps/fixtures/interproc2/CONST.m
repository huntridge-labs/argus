CONST ; inter-procedural negative: passes only a constant to SAFE
 ;
 ; The actual is a string literal, not a tainted variable, so SAFE's
 ; formal P must NOT become tainted.
 D RUN^SAFE("literal")
 Q
