INF ; argumentless FOR with no exit on the line = real infinite loop (FIRES)
 F  W "spin",!
 Q
SAFE ; argumentless FOR with an inline Q: exit must NOT fire
 N X S X=""
 F  S X=$O(^G(X)) Q:X=""  W X,!
 Q
DEV ; a device variable named F (USE/CLOSE/OPEN F) must NOT read as a FOR
 O F:(readonly):5
 U F
 C F
 Q
