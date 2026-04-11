package target

import "testing"

func TestCIDRGeneratorIteratesFullIPv4Range(t *testing.T) {
	iter, err := NewContainer([]string{"192.168.1.0/30"}, nil, false)
	if err != nil {
		t.Fatalf("NewContainer returned error: %v", err)
	}

	if got := iter.Count(); got != 4 {
		t.Fatalf("unexpected target count: got %d want 4", got)
	}

	expected := []string{
		"192.168.1.0",
		"192.168.1.1",
		"192.168.1.2",
		"192.168.1.3",
	}

	for _, want := range expected {
		ip := iter.Next()
		if ip == nil {
			t.Fatalf("expected %s, got nil", want)
		}
		if got := ip.String(); got != want {
			t.Fatalf("unexpected CIDR iteration result: got %s want %s", got, want)
		}
	}

	if extra := iter.Next(); extra != nil {
		t.Fatalf("expected iterator exhaustion, got %s", extra.String())
	}
}
