package fdepot

import (
	"context"
	"os"
	"testing"

	"github.com/deciduosity/certdepot"
	"github.com/deciduosity/certdepot/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBootstrapDepot(t *testing.T) {
	caName := "test_ca"
	depotName := "bootstrap_test"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() {
		assert.NoError(t, os.RemoveAll(depotName))
	}()

	impl := &testutil.BootstrapSuite{
		Name:        "FileDepot",
		ServiceName: "serviceca",
		CAName:      "fileca",
		Setup: func(t *testing.T, conf *certdepot.BootstrapDepotConfig) certdepot.Depot {
			require.NoError(t, os.MkdirAll(depotName, 0777))
			d, err := MakeFileDepot(depotName, certdepot.Options{CA: caName})
			require.NoError(t, err)
			return d
		},
		TearDown: func(t *testing.T) {
			require.NoError(t, os.RemoveAll(depotName))
		},
	}
	testutil.RunBootstrapSuite(ctx, t, impl)

}
