package openvpn

import (
	"testing"
)

func TestDCO_LogParser(t *testing.T) {
	testCases := []struct {
		logLine  string
		expected DCOStatus
	}{
		{
			logLine:  "2026-09-09 02:00:00 Data Channel Offload: using DCO device ovpn-dco0",
			expected: DCOStatusActive,
		},
		{
			logLine:  "Note: --disable-dco is present, DCO is disabled",
			expected: DCOStatusDisabled,
		},
		{
			logLine:  "Cannot open ovpn-dco device: No such device, DCO failed",
			expected: DCOStatusFailed,
		},
		{
			logLine:  "Initialization Sequence Completed",
			expected: "",
		},
	}

	for _, tc := range testCases {
		actual := ParseDCOLogLine(tc.logLine)
		if actual != tc.expected {
			t.Errorf("For line %q, expected %s, got %s", tc.logLine, tc.expected, actual)
		}
	}
}

func TestDCO_VersionSupport(t *testing.T) {
	v25 := &OpenVPNVersion{Major: 2, Minor: 5, Patch: 9}
	if v25.SupportsDisableDCO() {
		t.Errorf("OpenVPN 2.5.9 should not support --disable-dco flag")
	}

	v26 := &OpenVPNVersion{Major: 2, Minor: 6, Patch: 4}
	if !v26.SupportsDisableDCO() {
		t.Errorf("OpenVPN 2.6.4 should support --disable-dco flag")
	}

	v27 := &OpenVPNVersion{Major: 2, Minor: 7, Patch: 0}
	if !v27.SupportsDisableDCO() {
		t.Errorf("OpenVPN 2.7.0 should support --disable-dco flag")
	}
}
