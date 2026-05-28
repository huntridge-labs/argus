M003PIPE ; M003 fixture: tainted PIPE-device argument is shell injection
 ;
 ; YottaDB PIPE devices execute the COMMAND= parameter as a shell
 ; command. When that parameter is composed from a READ-tainted
 ; variable, the caller runs arbitrary shell. M003 must fire at
 ; CRITICAL severity (not just HIGH) for PIPE-device sites.
 R USERCMD
 O "PIPE":(COMMAND=USERCMD:READONLY)
 U "PIPE"
 W "shell ran",!
 C "PIPE"
 Q
