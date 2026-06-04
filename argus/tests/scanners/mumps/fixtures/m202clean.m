M202CLEAN ; M202 clean fixture: first label matches filename stem
 ;
 ; Filename stem (M202CLEAN) equals the first label name. The routine
 ; can be dispatched via ``D ^M202CLEAN``. M202 must NOT fire.
 W "matched filename",!
 Q
