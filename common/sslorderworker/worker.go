package sslorderworker

import "SamWaf/model/spec"

// Start keeps certificate issuance off the control loop that drains
// its host refresh messages. Orders stay serial because DNS providers share the
// process environment. The worker exits when orders is closed.
func Start(orders <-chan spec.ChanSslOrder, apply func(spec.ChanSslOrder)) {
	go func() {
		for order := range orders {
			apply(order)
		}
	}()
}
