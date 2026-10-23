package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpgradeStateRoundTripAndOldFileLoads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "u.json")
	assert.Equal(t, upgradeState{}, loadUpgradeState(p))
	require.NoError(t, os.WriteFile(p, []byte("{not json"), 0600))
	assert.Equal(t, upgradeState{}, loadUpgradeState(p))
	require.NoError(t, os.WriteFile(p, []byte("{}"), 0600))
	assert.Equal(t, upgradeState{}, loadUpgradeState(p))

	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	in := upgradeState{
		Last:     &upgradeResult{Result: "rejected", Version: "5.13.0", Reason: "rolled_back", RequestID: "r", EventID: "1:a", At: at},
		Rejected: &rejectedUpgrade{Version: "5.13.0", SHA256: "s", RequestID: "r"},
		Pending: &pendingUpgrade{Target: upgradeRef{"5.13.0", "t"}, Previous: upgradeRef{"5.12.1", "p"},
			PreviousPkg: "/x/prev.deb", RequestID: "r", StartedAt: at, Installed: true},
	}
	require.NoError(t, saveUpgradeState(p, in))
	assert.Equal(t, in, loadUpgradeState(p))
	fi, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
}

func TestUpgradeStatePathIsProtected(t *testing.T) {
	appConfig.OsqueryFlagFile = "/etc/osquery/osquery.flags"
	t.Cleanup(func() { appConfig = Configuration{} })
	assert.Equal(t, "/etc/osquery/osquery.flags.osctrld-upgrade-state.json", upgradeStatePath())
	assert.Contains(t, protectedFiles(), upgradeStatePath())
}

var (
	testSHAT = strings.Repeat("a", 64)
	testSHAP = strings.Repeat("b", 64)
	testReq1 = strings.Repeat("1", 32)
	testReq2 = strings.Repeat("2", 32)
)

func validRes() upgradeResolution {
	return upgradeResolution{RequestID: testReq1, Target: &upgradeRef{"5.13.0", testSHAT}, Previous: &upgradeRef{"5.12.1", testSHAP}}
}

func TestShouldAttemptValidResolutionAttempts(t *testing.T) {
	ok, why := shouldAttempt(validRes(), upgradeState{})
	assert.True(t, ok)
	assert.Empty(t, why)
}

func TestShouldAttemptRejectsMalformedDigest(t *testing.T) {
	for _, d := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 65)} {
		r := validRes()
		r.Target.SHA256 = d
		ok, why := shouldAttempt(r, upgradeState{})
		assert.False(t, ok, d)
		assert.Equal(t, "invalid_resolution", why)
		r = validRes()
		r.Previous.SHA256 = d
		ok, why = shouldAttempt(r, upgradeState{})
		assert.False(t, ok, d)
		assert.Equal(t, "invalid_resolution", why)
	}
}

func TestShouldAttemptRejectsMissingPrevious(t *testing.T) {
	r := validRes()
	r.Previous = nil
	ok, why := shouldAttempt(r, upgradeState{})
	assert.False(t, ok)
	assert.Equal(t, "invalid_resolution", why)
}

func TestShouldAttemptRejectsBadVersionAndRequestID(t *testing.T) {
	for _, v := range []string{"", "5", "5.13.0.1.2", "5.13.x", "v5.13.0", "5.13.0; rm"} {
		r := validRes()
		r.Target.Version = v
		ok, why := shouldAttempt(r, upgradeState{})
		assert.False(t, ok, v)
		assert.Equal(t, "invalid_resolution", why)
		r = validRes()
		r.Previous.Version = v
		ok, _ = shouldAttempt(r, upgradeState{})
		assert.False(t, ok, v)
	}
	for _, id := range []string{"", "3f2a", strings.Repeat("A", 32), strings.Repeat("1", 33)} {
		r := validRes()
		r.RequestID = id
		ok, why := shouldAttempt(r, upgradeState{})
		assert.False(t, ok, id)
		assert.Equal(t, "invalid_resolution", why)
	}
}

func TestShouldAttemptServerReasonSkips(t *testing.T) {
	ok, why := shouldAttempt(upgradeResolution{Reason: "ahead_of_target"}, upgradeState{})
	assert.False(t, ok)
	assert.Equal(t, "ahead_of_target", why)
	ok, why = shouldAttempt(upgradeResolution{}, upgradeState{})
	assert.False(t, ok)
	assert.Equal(t, "no_target", why)
}

func TestShouldAttemptRejectedSameRequestIdSkips(t *testing.T) {
	res := validRes()
	st := upgradeState{Rejected: &rejectedUpgrade{Version: "5.13.0", SHA256: testSHAT, RequestID: testReq1}}
	ok, why := shouldAttempt(res, st)
	assert.False(t, ok)
	assert.Equal(t, "rejected", why)
}

func TestShouldAttemptNewRequestIdRetries(t *testing.T) {
	res := validRes()
	res.RequestID = testReq2
	for _, rej := range []rejectedUpgrade{
		{Version: "5.13.0", SHA256: testSHAT, RequestID: testReq1},
		{Version: "5.14.0", SHA256: testSHAT, RequestID: testReq2},
		{Version: "5.13.0", SHA256: testSHAP, RequestID: testReq2},
	} {
		ok, why := shouldAttempt(res, upgradeState{Rejected: &rej})
		assert.True(t, ok)
		assert.Empty(t, why)
	}
	ok, _ := shouldAttempt(res, upgradeState{})
	assert.True(t, ok)
}
