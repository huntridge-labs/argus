M212INF ; M212 fixture: argumentless FOR with no exit
 ;
 ; ``F  W "spin"`` has no QUIT / GOTO / HALT on the loop line, so it
 ; iterates forever. M212 must fire.
 F  W "spin",!
 Q
