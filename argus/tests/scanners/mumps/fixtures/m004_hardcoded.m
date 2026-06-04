M004HC ; M004 fixture: hard-coded credentials in globals
 ;
 ; Two credential-shaped globals with literal values. M004 must fire
 ; twice and the literal values must be redacted in the findings.
 S ^CONFIG("DB","PASSWORD")="hunter2"
 S ^APP("API_KEY")="sk_live_abcdef123456"
 Q
