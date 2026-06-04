MENUDRV ; $TEXT-driven menu dispatch is a fixed table, not attacker RCE
 ;
 ; OPT is READ-tainted, but X = $T(MENU+OPT) is the routine's OWN source
 ; line (a fixed dispatch table). The value dispatched is a hardcoded
 ; entryref selected by a numeric line offset, not external code. Tainting
 ; X because the offset OPT is tainted is a false positive, so M005 (and
 ; M002) must NOT fire on the @ dispatch here.
RUN ;
 N X,OPT
 R "Option: ",OPT
 S X=$T(MENU+OPT)
 D @$P(X,";",4)
 Q
MENU ; dispatch table
 ;;1;Add patient;ADD^APP
 ;;2;Edit patient;EDIT^APP
