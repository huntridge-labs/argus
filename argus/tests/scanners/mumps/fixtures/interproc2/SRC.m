SRC ; inter-procedural source: READ-taints CMD, passes it to SINK
 ;
 ; SRC itself has no sink — the XECUTE happens in SINK. One-hop
 ; propagation must carry CMD's taint into SINK's formal P.
 R CMD
 D RUN^SINK(CMD)
 Q
