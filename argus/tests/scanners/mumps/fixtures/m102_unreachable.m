M102UNR ; M102 fixture: dead code on the SAME line as an unconditional break
 ;
 ; A command after an unconditional Q / H on the SAME physical line never
 ; executes. M102 flags this (the unambiguous case) and fires twice here.
 ; Cross-line "dead" code and IF-guarded quits (the NOTDEAD label below)
 ; are intentionally NOT flagged: on real code the grammar cannot tell
 ; them from reachable next-line code (dot-blocks, separate statements,
 ; labels), which produced ~100% false positives.
 Q  W "after quit (unreachable)",!
DEADHALT ;
 H  W "after halt (unreachable)",!
NOTDEAD ; cross-line + conditional breaks must NOT fire
 Q
 W "reachable: separate statement on its own line",!
 I X=1 Q  ; conditional quit governs only the rest of THIS line
 W "reachable: new line after an IF-guarded quit",!
 Q
