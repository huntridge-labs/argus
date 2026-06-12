M203EXT ; M203 clean: well-known VistA vars are externally defined
 ;
 ; DUZ (current user) and U ("^") are set by the Kernel sign-on, not
 ; this routine. They are on the known_external_vars allowlist, so
 ; M203 must NOT flag them as read-before-defined.
 W "User #",DUZ,U,"caret",!
 Q
