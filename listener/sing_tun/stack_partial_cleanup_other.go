//go:build !with_gvisor

package sing_tun

import tun "github.com/metacubex/sing-tun"

// Mixed is unavailable in this build; System.Close handles partial startup.
func stackAfterStartFailure(stack tun.Stack) tun.Stack {
	return stack
}
