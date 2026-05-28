M003OPN ; M003 fixture: READ-tainted variable reaches OPEN device argument
 ;
 ; A tainted device-spec routed into OPEN/USE is OS command injection
 ; on PIPE devices and arbitrary I/O redirection elsewhere. M003 must
 ; fire on the OPEN site (and on the subsequent USE for the same var).
 W "Enter device: "
 R DEV
 O DEV
 U DEV
 W "wrote to attacker-chosen device",!
 C DEV
 Q
