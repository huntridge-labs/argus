M216Z ; M216 fixture: non-portable $Z function vs a standard intrinsic
 ;
 ; $ZD is vendor-specific; $P ($PIECE) is standard. M216 must fire only
 ; on $ZD.
 S Y=$ZD(X,1)
 S Z=$P(X,U,1)
 Q
