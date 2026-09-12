package main

import "testing"

func TestDefaultRouteDevice(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "active slot",
			output: "default dev tun3 scope link\n",
			want:   "tun3",
		},
		{
			name:   "ignore endpoint route before default",
			output: "203.0.113.9 via 192.0.2.1 dev eth0\ndefault dev tun4\n",
			want:   "tun4",
		},
		{
			name:   "fail closed table",
			output: "unreachable default metric 42760\n",
			want:   "",
		},
		{
			name:   "empty table",
			output: "",
			want:   "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := defaultRouteDevice(test.output); got != test.want {
				t.Fatalf("defaultRouteDevice() = %q, want %q", got, test.want)
			}
		})
	}
}
