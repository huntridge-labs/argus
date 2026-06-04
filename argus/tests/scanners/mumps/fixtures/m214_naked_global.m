M214NK ; M214 fixture: naked global reference vs named
 ;
 ; ^DPT(1) is a named reference (clean); ^(2) is naked and resolves
 ; against the last global referenced. M214 must fire only on ^(2).
 S ^DPT(1)="a"
 S ^(2)="b"
 Q
