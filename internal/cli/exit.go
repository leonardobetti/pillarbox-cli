package cli

// Process exit codes, PRD section 9.
const (
	ExitOK        = 0 // success
	ExitOther     = 1 // other error
	ExitUsage     = 2 // usage error
	ExitAuth      = 3 // authentication failed
	ExitIntegrity = 4 // integrity failure
	ExitKeystore  = 5 // keystore missing or invalid
)
