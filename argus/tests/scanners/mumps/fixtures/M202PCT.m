%M202PCT ; M202 clean: percent-routine label matches filename after %-strip
 ;
 ; VistA percent-routines declare a ``%NAME`` label but are stored as
 ; the bare (or underscore) filename. Stripping the leading ``%``
 ; makes ``%M202PCT`` match the ``M202PCT`` file stem. M202 must NOT
 ; fire.
 W "percent routine",!
 Q
