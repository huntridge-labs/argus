WRONGNAME ; M202 fixture: first label does not match filename stem
 ;
 ; Filename stem is M202MISMATCH but the first label is WRONGNAME.
 ; GT.M / YottaDB / Cache will fail to dispatch ``D ^M202MISMATCH``.
 ; M202 must fire.
 W "this routine cannot be invoked by filename",!
 Q
