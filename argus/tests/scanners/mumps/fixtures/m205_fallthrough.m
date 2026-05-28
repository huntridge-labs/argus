M205FT ; M205 fixture: LABELA falls through into LABELB
 ;
 ; LABELA's body ends without a Q. ``D LABELA`` runs LABELA then
 ; continues into LABELB; callers do not expect that. M205 must fire
 ; on LABELB (the label being reached by fallthrough).
 D LABELA
 Q
LABELA
 W "first",!
LABELB
 W "fallthrough",!
 Q
