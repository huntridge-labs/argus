M003CLN ; M003 clean fixture: OPEN with constant device
 ;
 ; OPEN/USE arguments are constants baked into source. M003 must NOT
 ; fire — the device name cannot be influenced by external input.
 O 50:"foo.dat":10
 U 50
 W "static device only",!
 C 50
 Q
