M102UNR ; M102 fixture: unreachable code after unconditional break
 ;
 ; Unconditional Q and unconditional H both end the scope. The W
 ; statements immediately after them never execute. M102 must fire
 ; twice (once per orphan command).
 W "before quit",!
 Q
 W "after quit (unreachable)",!
NEXTLBL ; second label entry
 W "before halt",!
 H
 W "after halt (unreachable)",!
