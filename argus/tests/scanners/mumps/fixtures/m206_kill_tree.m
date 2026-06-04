M206KT ; M206 fixture: KILL of entire global tree
 ;
 ; ``K ^DATA`` deletes the entire ``^DATA`` global from the database
 ; — every record under every subscript. Almost always a typo for
 ; ``K ^DATA(IEN)``. M206 must fire.
 K ^DATA
 K ^TEMP("scratch")
 Q
