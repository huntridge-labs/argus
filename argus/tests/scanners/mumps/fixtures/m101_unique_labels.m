M101UNQ ; M101 clean fixture: every label is declared once
 ;
 ; ``STEP1`` and ``STEP2`` are distinct labels. M101 must NOT fire.
 D STEP1
 D STEP2
 Q
STEP1 ; first label
 W "step 1",!
 Q
STEP2 ; second label
 W "step 2",!
 Q
