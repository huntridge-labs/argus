SUPPRESS ; inline ignore-directive handling
 ;
 ; The first XECUTE is silenced by an inline ignore for M001; the second
 ; is not and must still fire.
 R A
 X "DO "_A ;argus:ignore[M001]
 R B
 X "DO "_B
 Q
