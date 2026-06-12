M001ZIO ; M001 fixture: $ZIO is a custom taint source (config-driven)
 ;
 ; $ZIO is a YottaDB/GT.M intrinsic that returns the current device's
 ; pending input. With M001's built-in source set it is NOT
 ; recognized; users opt in via taint_sources.patterns in argus.yml.
 ; This fixture validates that opt-in path.
 S CMD=$ZIO
 X CMD
 Q
