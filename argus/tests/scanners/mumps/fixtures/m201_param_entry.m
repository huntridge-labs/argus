M201PE ; M201: parameterized entry labels resolve their callers
 ;
 ; D WARNING("hi") resolves against the WARNING(MSG) label even though the
 ; grammar does not reliably emit a parameterized label as a label node.
 ; A genuinely undefined label (NOPE) still fires.
EN ;
 D WARNING("hi")
 D NOPE
 Q
WARNING(MSG) ; parameterized entry
 W MSG
 Q
