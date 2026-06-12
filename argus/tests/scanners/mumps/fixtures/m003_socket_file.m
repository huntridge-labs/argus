M003DEV ; M003: device taxonomy grades by blast radius
 ;
 ; A tainted socket target is SSRF (HIGH); a tainted file path is path
 ; traversal (MEDIUM). PIPE (RCE / CRITICAL) is covered by m003_pipe_taint.
SOCK ;
 R HOST
 O HOST:(connect=HOST:"":"TCP")
 Q
FILE ;
 R PATH
 O PATH:(newversion:recordsize=255)
 Q
