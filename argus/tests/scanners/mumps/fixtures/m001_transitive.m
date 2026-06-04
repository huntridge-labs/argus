TAG ; multi-hop taint chain: READ -> concat -> concat -> XECUTE must FIRE
 R ARG
 S PART="DO "_ARG
 S CMD=PART_" SOMETHING"
 X CMD
 Q
