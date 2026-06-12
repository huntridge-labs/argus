M006PURE ; M006: a provably-pure $& helper carries no injection risk
 ;
 ; $&STRLEN is pure (returns a length) — must NOT fire even with a tainted
 ; argument. $ZF(-1,cmd) execs a shell command — CRITICAL.
PURE ;
 R DATA
 S LEN=$&STRLEN(DATA)
 Q
SHELL ;
 R CMD
 S RC=$ZF(-1,CMD)
 Q
