TRAV ; X is READ-tainted then reassigned to a $ORDER traversal value
 ;
 ; The later @(X) is an executable expression indirection, but X now holds
 ; a structure subscript key (the traversal value), not the external input,
 ; so M002 must NOT fire — the traversal-iterator untaint.
 R X
 F  S X=$O(^G(X)) Q:X=""  S Z=@(X)
 Q
