package fdepot

import (
	"github.com/deciduosity/certdepot"
	"github.com/pkg/errors"
	"github.com/square/certstrap/depot"
)

type fileDepot struct {
	*depot.FileDepot
}

// MakeFileDepot constructs a file-based depot implementation and
// allows users to specify options for the default CA name and
// expiration time.
func MakeFileDepot(dir string, opts certdepot.Options) (certdepot.Depot, error) {
	dt, err := depot.NewFileDepot(dir)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return certdepot.MakeDepot(dt, opts), nil
}
