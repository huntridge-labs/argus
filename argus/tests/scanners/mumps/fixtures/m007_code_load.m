M007CL ; M007: tainted source loaded / compiled as code
 ;
 ; ZLINK of a READ-tainted routine name links attacker-chosen code, and
 ; ZINSERT of a tainted line injects code into the buffer. A literal ZLINK
 ; is safe and must not fire.
LINK ;
 R RTN
 ZLINK RTN
 Q
INS ;
 R LINE
 ZINSERT LINE
 Q
SAFE ;
 ZLINK "XUSER"
 Q
