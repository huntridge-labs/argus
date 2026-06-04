M212OK ; M212 clean fixture: argumentless FOR with inline exit + counted FOR
 ;
 ; The $ORDER walk carries a ``Q:X=""`` exit on the loop line, and the
 ; second loop is counted (has a controller). M212 must NOT fire on
 ; either.
 S X=""
 F  S X=$O(^G(X)) Q:X=""  W X,!
 F I=1:1:3 W I,!
 Q
