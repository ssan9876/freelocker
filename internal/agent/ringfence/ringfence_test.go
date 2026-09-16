package ringfence

import (
	"context"
	"testing"
)

func TestRuleNameIsStableAndScoped(t *testing.T) {
	a := RuleName(`C:\Program Files\App\app.exe`)
	if a != RuleName(`C:\Program Files\App\app.exe`) {
		t.Error("rule name must be deterministic")
	}
	if a == RuleName(`C:\Other\app.exe`) {
		t.Error("different programs must get different rule names")
	}
	if len(a) < len(RulePrefix) || a[:len(RulePrefix)] != RulePrefix {
		t.Errorf("rule name %q must start with %q so reconcile can enumerate ours", a, RulePrefix)
	}
}

func TestDiffAddsMissingAndRemovesStale(t *testing.T) {
	keep := Program{Path: `C:\keep.exe`, NetworkBlocked: true}
	want := map[string]Program{RuleName(keep.Path): keep}
	existing := []string{RuleName(keep.Path), RulePrefix + "deadbeefdeadbeef"}

	add, remove := Diff(existing, want)
	if len(add) != 0 {
		t.Errorf("add = %+v, want none (the rule is already there)", add)
	}
	if len(remove) != 1 || remove[0] != RulePrefix+"deadbeefdeadbeef" {
		t.Errorf("remove = %+v, want the stale rule only", remove)
	}

	// A program with no rule yet must be added.
	add, remove = Diff(nil, want)
	if len(add) != 1 || add[0].Path != keep.Path || len(remove) != 0 {
		t.Errorf("add = %+v remove = %+v, want one add", add, remove)
	}

	// A listed program that is not network-blocked gets no rule at all.
	open := map[string]Program{RuleName(`C:\open.exe`): {Path: `C:\open.exe`, NetworkBlocked: false}}
	if add, _ := Diff(nil, open); len(add) != 0 {
		t.Errorf("add = %+v, want none for a program that is not network-blocked", add)
	}

	// A program that HAS a rule but is no longer network-blocked must have
	// its rule removed — this is how an admin un-blocks an app.
	unblocked := Program{Path: `C:\unblocked.exe`, NetworkBlocked: false}
	name := RuleName(unblocked.Path)
	add, remove = Diff([]string{name}, map[string]Program{name: unblocked})
	if len(add) != 0 {
		t.Errorf("add = %+v, want none", add)
	}
	if len(remove) != 1 || remove[0] != name {
		t.Errorf("remove = %+v, want the rule for the no-longer-blocked program", remove)
	}
}

func TestNoopEnforcerRecordsWithoutTouchingTheHost(t *testing.T) {
	var e NoopEnforcer
	rf := Ringfence{Version: "v1", Mode: "audit", Programs: []Program{{Path: `C:\a.exe`, NetworkBlocked: true}}}
	if err := e.Apply(context.Background(), rf); err != nil {
		t.Fatal(err)
	}
	if got := e.Status(); got.Applied != "v1" {
		t.Errorf("status = %+v, want the applied version", got)
	}
}
