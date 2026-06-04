M101DUP ; M101 fixture: duplicate label declared in routine
 ;
 ; ``DOTHING`` is declared twice. The second declaration silently
 ; shadows the first; M101 must fire on the second declaration.
 D DOTHING
 Q
DOTHING ; first declaration
 W "first",!
 Q
DOTHING ; duplicate declaration
 W "second",!
 Q
