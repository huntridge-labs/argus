M213QA ; M213 fixture: QUIT with an argument inside a FOR loop
 ;
 ; ``Q 5`` inside the loop returns a value / ends the loop after one
 ; iteration — a bug outside an extrinsic. M213 must fire.
 F I=1:1:3 Q 5
 Q
