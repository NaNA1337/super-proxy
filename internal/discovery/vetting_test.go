package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/stretchr/testify/require"
)

func TestVetNodesCompletesAdmissionBeforeCandidateStatus(t *testing.T) {
	ClearOVPNSecretCache()
	defer ClearOVPNSecretCache()
	nodes := []models.Node{
		{ID: "clean", IP: "198.51.100.1", Status: models.StatusDiscovered, Score: 9999},
		{ID: "bad", IP: "198.51.100.2", Status: models.StatusDiscovered, Score: 9999},
	}
	SetOVPNSecret("clean", "credential")
	SetOVPNSecret("bad", "credential")

	vetted, summary := VetNodes(context.Background(), nodes, 2, func(_ context.Context, node *models.Node) (*reputation.Result, error) {
		ip := node.IP
		if ip == "198.51.100.2" {
			return &reputation.Result{IP: ip, Status: reputation.StatusBad, HardReject: true,
				ProviderReason: "public proxy", NetworkInfo: models.NetworkClass{IsProxy: true}}, errors.New("public proxy")
		}
		return &reputation.Result{IP: ip, Status: reputation.StatusGood,
			ProviderReason: "clean residential", NetworkInfo: models.NetworkClass{ASN: "AS64500", NetworkType: "residential"}}, nil
	}, func(*models.Node) int { return 90 })

	require.Equal(t, VettingSummary{Accepted: 1, Rejected: 1}, summary)
	require.Equal(t, models.StatusReputationChecked, vetted[0].Status)
	require.Equal(t, 90, vetted[0].Score, "source score must be replaced by internal score")
	require.Equal(t, "AS64500", vetted[0].NetClass.ASN)
	require.Equal(t, models.StatusFailed, vetted[1].Status)
	_, credentialExists := GetOVPNSecret("bad")
	require.False(t, credentialExists)
}
