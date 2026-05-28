M004CLN ; M004 clean fixture: no credentials in globals
 ;
 ; Globals are used but subscripts are not credential-shaped and the
 ; values are not literals; nothing for M004 to flag.
 S ^TMP("SESSION",$J,"COUNT")=0
 S ^USER("LAST_LOGIN",U)=$H
 Q
