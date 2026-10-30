package auth

import (
	"net"
	"testing"
)

// CVE-2026-98432 is a Linux kernel use-after-free in the IPv4 TCP handshake.
// Its published exploit needs an MPTCP listener, and Go 1.24+ opens every
// listener as MPTCP by default when the kernel supports it. The OAuth callback
// listens on every interface (net.Listen("tcp", ":"+callbackPort)), so on a
// Linux machine whose kernel is not patched yet, `cybedefend login` exposed an
// MPTCP listener to the network for the length of the login. go.mod turns the
// default off (`godebug multipathtcp=0`), as the Go Security Team advises.
func TestListenersDoNotUseMultipathTCP(t *testing.T) {
	var lc net.ListenConfig // what net.Listen uses
	if lc.MultipathTCP() {
		t.Fatal("listeners default to MPTCP: keep `godebug multipathtcp=0` in go.mod (CVE-2026-98432)")
	}
}
