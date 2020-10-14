package fdepot

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/deciduosity/certdepot"
	"github.com/deciduosity/certdepot/testutil"
	"github.com/square/certstrap/depot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDepot(t *testing.T) {
	var tempDir string
	var err error

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	impl := &testutil.DepotCase{
		Name: "File",
		Setup: func() certdepot.Depot {
			tempDir, err = ioutil.TempDir(".", "file_depot")
			require.NoError(t, err)
			d, err := MakeFileDepot(tempDir, certdepot.Options{})
			require.NoError(t, err)
			return d
		},
		Check: func(t *testing.T, tag *depot.Tag, data []byte) {
			path := getTagPath(tag)

			if data == nil {
				_, err = os.Stat(filepath.Join(tempDir, path))
				assert.True(t, os.IsNotExist(err))
				return
			}

			var fileData []byte
			fileData, err = ioutil.ReadFile(filepath.Join(tempDir, path))
			require.NoError(t, err)
			assert.Equal(t, data, fileData)
		},
		Cleanup: func() {
			require.NoError(t, os.RemoveAll(tempDir))
		},
		Tests: []testutil.DepotTest{
			{
				Name: "PutFailsWithExisting",
				Test: func(t *testing.T, d certdepot.Depot) {
					const name = "bob"

					assert.NoError(t, d.Put(depot.PrivKeyTag(name), []byte("data")))
					assert.Error(t, d.Put(depot.PrivKeyTag(name), []byte("other data")))

					assert.NoError(t, d.Put(depot.CsrTag(name), []byte("data")))
					assert.Error(t, d.Put(depot.CsrTag(name), []byte("other data")))

					assert.NoError(t, d.Put(depot.CrlTag(name), []byte("data")))
					assert.Error(t, d.Put(depot.CrlTag(name), []byte("other data")))
				},
			},
			{
				Name: "DeleteWhenDNE",
				Test: func(t *testing.T, d certdepot.Depot) {
					const name = "bob"

					assert.Error(t, d.Delete(depot.CrtTag(name)))
					assert.Error(t, d.Delete(depot.PrivKeyTag(name)))
					assert.Error(t, d.Delete(depot.CsrTag(name)))
					assert.Error(t, d.Delete(depot.CrlTag(name)))
				},
			},
		},
	}

	t.Run(impl.Name, func(t *testing.T) { impl.Run(ctx, t) })
}
