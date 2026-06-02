M204DECL ; M204 fixture: a dead NEW/READ declaration fires; a dead SET does not
 ;
 ; LEFTOVER is NEWed but never read — a dead declaration M204 flags.
 ; SETONLY is assigned but never read; that is NOT flagged — a SET value
 ; is often consumed by a callee via implicit-NEW inheritance, the
 ; FP-prone case the Phase 1 intra-routine pass cannot see.
 ; USED is read, so it never flags.
 N LEFTOVER
 S USED="alive"
 S SETONLY="quiet"
 W USED,!
 Q
