//go:build with_gvisor

package sing_tun

import tun "github.com/metacubex/sing-tun"

// stackAfterStartFailure selects the owner for New's deferred cleanup.
// sing-tun v0.4.22 Mixed.Start starts System before creating its gVisor stack,
// but Mixed.Close does nothing when that gVisor stack is nil. Every error
// return in Mixed.Start precedes publication of the gVisor stack, so close
// System directly on failure. On success retain Mixed.Close, which already
// closes System; never close both owners.
func stackAfterStartFailure(stack tun.Stack) tun.Stack {
	if mixed, ok := stack.(*tun.Mixed); ok {
		return mixed.System
	}
	return stack
}
