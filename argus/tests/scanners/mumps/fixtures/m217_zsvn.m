M217Z ; M217 fixture: non-portable $Z special variable vs a standard one
 ;
 ; $ZV is vendor-specific; $H ($HOROLOG) is standard. M217 must fire
 ; only on $ZV.
 S Y=$ZV
 S Z=$H
 Q
