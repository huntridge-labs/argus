M001CGI ; M001 fixture: HTTP context global flows into XECUTE
 ;
 ; ``^%CGI(...)`` carries per-request input on legacy VistA web stacks.
 ; Treating that value as code is RCE. M001 must fire.
 S CMD=^%CGI("QUERY_STRING")
 X CMD
 Q
