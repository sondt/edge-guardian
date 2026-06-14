package detect

import (
	"testing"
	"time"
)

func TestHitsCounter(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	c := Hits(3, time.Minute)
	if _, tripped := c.Record("ip", "", base); tripped {
		t.Fatal("should not trip on 1st")
	}
	c.Record("ip", "", base.Add(time.Second))
	if count, tripped := c.Record("ip", "", base.Add(2*time.Second)); count != 3 || !tripped {
		t.Fatalf("count=%d tripped=%v want 3,true", count, tripped)
	}
	// sub is ignored for hit counting.
	c2 := Hits(2, time.Minute)
	c2.Record("ip", "aaa", base)
	if _, tripped := c2.Record("ip", "bbb", base); !tripped {
		t.Fatal("hit counter should ignore sub and trip on 2nd hit")
	}
}

func TestDistinctCounter(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("counts distinct subs, not repeats", func(t *testing.T) {
		d := NewDistinct(3, time.Minute)
		// Same port hit many times = 1 distinct.
		d.Record("1.1.1.1", "22", base)
		d.Record("1.1.1.1", "22", base.Add(time.Second))
		if _, tripped := d.Record("1.1.1.1", "22", base.Add(2*time.Second)); tripped {
			t.Fatal("repeated same port must not trip a distinct-port scan")
		}
		// Now three distinct ports.
		d.Record("1.1.1.1", "23", base.Add(3*time.Second))
		count, tripped := d.Record("1.1.1.1", "80", base.Add(4*time.Second))
		if count != 3 || !tripped {
			t.Fatalf("count=%d tripped=%v want 3,true (22,23,80)", count, tripped)
		}
	})

	t.Run("old subs slide out of window", func(t *testing.T) {
		d := NewDistinct(3, time.Minute)
		d.Record("2.2.2.2", "1", base)
		d.Record("2.2.2.2", "2", base.Add(time.Second))
		// 70s later the first two are stale; only the new one counts.
		count, tripped := d.Record("2.2.2.2", "3", base.Add(70*time.Second))
		if count != 1 || tripped {
			t.Fatalf("count=%d tripped=%v want 1,false", count, tripped)
		}
	})

	t.Run("distinct keys independent", func(t *testing.T) {
		d := NewDistinct(2, time.Minute)
		d.Record("a", "1", base)
		if _, tripped := d.Record("b", "1", base); tripped {
			t.Fatal("key b should not inherit key a's count")
		}
	})

	t.Run("forget and prune", func(t *testing.T) {
		d := NewDistinct(5, time.Minute)
		d.Record("x", "1", base)
		d.Record("x", "2", base)
		d.Forget("x")
		if c, _ := d.Record("x", "3", base.Add(time.Second)); c != 1 {
			t.Fatalf("after Forget count=%d want 1", c)
		}
		d.Record("y", "1", base)
		d.Prune(base.Add(2 * time.Minute))
		if c, _ := d.Record("y", "9", base.Add(2*time.Minute)); c != 1 {
			t.Fatalf("after Prune count=%d want 1", c)
		}
	})
}
