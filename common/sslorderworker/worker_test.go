package sslorderworker

import (
	"SamWaf/model/spec"
	"testing"
	"time"
)

// A shared certificate can refresh more hosts than the control channel can hold.
// Starting the order worker must return so the control loop can drain those messages.
func TestSSLOrderWorkerRefreshesNineteenHosts(t *testing.T) {
	orders := make(chan spec.ChanSslOrder, 1)
	orders <- spec.ChanSslOrder{Type: 7, Content: "wildcard-order"}
	close(orders)
	refreshes := make(chan int, 10)
	started := make(chan spec.ChanSslOrder, 1)
	completed := make(chan struct{})
	returned := make(chan struct{})
	cancel := make(chan struct{})
	t.Cleanup(func() {
		close(cancel)
		select {
		case <-completed:
		case <-time.After(3 * time.Second):
			t.Error("order handler did not stop")
		}
		select {
		case <-returned:
		case <-time.After(3 * time.Second):
			t.Error("worker startup did not return")
		}
	})

	go func() {
		Start(orders, func(order spec.ChanSslOrder) {
			defer close(completed)
			started <- order
			for host := 0; host < 19; host++ {
				select {
				case refreshes <- host:
				case <-cancel:
					return
				}
			}
		})
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatalf("SSL worker blocked control loop startup; %d refreshes queued", len(refreshes))
	}
	select {
	case order := <-started:
		if order.Type != 7 || order.Content != "wildcard-order" {
			t.Fatalf("wrong order dispatched: %#v", order)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("order did not start")
	}
	for want := 0; want < 19; want++ {
		select {
		case got := <-refreshes:
			if got != want {
				t.Fatalf("refresh = %d, want %d", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("host %d was not refreshed", want)
		}
	}
	select {
	case <-completed:
	case <-time.After(3 * time.Second):
		t.Fatal("order could not finish after refreshing all hosts")
	}
}

// DNS providers use process environment variables, so orders must stay serial.
func TestSSLOrderWorkerPreservesOrderAndSerialExecution(t *testing.T) {
	orders := make(chan spec.ChanSslOrder, 2)
	orders <- spec.ChanSslOrder{Type: 1}
	orders <- spec.ChanSslOrder{Type: 2}
	close(orders)
	started := make(chan int, 2)
	finished := make(chan int, 2)
	releaseFirst := make(chan struct{})
	t.Cleanup(func() {
		close(releaseFirst)
		for i := 0; i < 2; i++ {
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Error("order handler did not finish")
			}
		}
	})
	Start(orders, func(order spec.ChanSslOrder) {
		started <- order.Type
		if order.Type == 1 {
			<-releaseFirst
		}
		finished <- order.Type
	})
	select {
	case got := <-started:
		if got != 1 {
			t.Fatalf("first order = %d, want 1", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first order did not start")
	}
	select {
	case got := <-started:
		t.Fatalf("order %d started before the first order finished", got)
	case <-time.After(100 * time.Millisecond):
	}
}
