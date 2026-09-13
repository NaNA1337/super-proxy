package xray

import "testing"

func TestValidateRuntimeRuleTargetRequiresExactBalancer(t *testing.T) {
	valid := &runtimeRoutingRule{RuleTag: "active-balancer-rule-vless", BalancerTag: "balancer-0-1-2"}
	if err := validateRuntimeRuleTarget(valid, []int{0, 1, 2}); err != nil {
		t.Fatalf("valid VLESS target rejected: %v", err)
	}

	stale := &runtimeRoutingRule{RuleTag: "active-balancer-rule-vless", Tag: "block"}
	if err := validateRuntimeRuleTarget(stale, []int{0, 1, 2}); err == nil {
		t.Fatal("blocking VLESS rule was accepted while three slots were expected")
	}

	exposedWrongBalancer := &runtimeRoutingRule{RuleTag: "active-balancer-rule-vless", BalancerTag: "balancer-0-1"}
	if err := validateRuntimeRuleTarget(exposedWrongBalancer, []int{0, 1, 2}); err == nil {
		t.Fatal("mismatched VLESS balancer was accepted when Xray exposed it")
	}
}
