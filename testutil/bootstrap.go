package testutil

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/alecthomas/assert"
	"github.com/deciduosity/certdepot"
	"github.com/square/certstrap/depot"
	"github.com/stretchr/testify/require"
)

type BootstrapConfigCase struct {
	Name  string
	Depot certdepot.Depot
	Conf  certdepot.BootstrapDepotConfig
	Fail  bool
}

type BootstrapSuite struct {
	Name        string
	Setup       func(*testing.T, *certdepot.BootstrapDepotConfig) certdepot.Depot
	TearDown    func(*testing.T)
	ServiceName string
	CAName      string
}

type BootstrapCase struct {
	Name  string
	Setup func(*testing.T, certdepot.Depot)
	Conf  certdepot.BootstrapDepotConfig
	Test  func(*testing.T, certdepot.Depot)
	Fail  bool
}

func RunBootstrapSuite(ctx context.Context, t *testing.T, impl *BootstrapSuite) {
	for _, test := range []BootstrapCase{
		{
			Name: "ExistingCertsInDepot",
			Conf: certdepot.BootstrapDepotConfig{
				CAName:      impl.CAName,
				ServiceName: impl.ServiceName,
			},
			Setup: func(t *testing.T, d certdepot.Depot) {
				assert.NoError(t, d.Put(depot.CrtTag(impl.CAName), []byte("fake ca cert")))
				assert.NoError(t, d.Put(depot.PrivKeyTag(impl.CAName), []byte("fake ca key")))
				assert.NoError(t, d.Put(depot.CrtTag(impl.ServiceName), []byte("fake service cert")))
				assert.NoError(t, d.Put(depot.PrivKeyTag(impl.ServiceName), []byte("fake service key")))
			},
			Test: func(t *testing.T, d certdepot.Depot) {
				data, err := d.Get(depot.CrtTag(impl.CAName))
				assert.NoError(t, err)
				assert.Equal(t, data, []byte("fake ca cert"))
				data, err = d.Get(depot.PrivKeyTag(impl.CAName))
				assert.NoError(t, err)
				assert.Equal(t, data, []byte("fake ca key"))
				data, err = d.Get(depot.CrtTag(impl.ServiceName))
				assert.NoError(t, err)
				assert.Equal(t, data, []byte("fake service cert"))
				data, err = d.Get(depot.PrivKeyTag(impl.ServiceName))
				assert.NoError(t, err)
				assert.Equal(t, data, []byte("fake service key"))
			},
		},
		{
			Name: "CertCreation",
			Conf: certdepot.BootstrapDepotConfig{
				CAName:      impl.CAName,
				ServiceName: impl.ServiceName,
				CAOpts: &certdepot.CertificateOptions{
					CommonName: impl.CAName,
					Expires:    time.Hour,
				},
				ServiceOpts: &certdepot.CertificateOptions{
					CommonName: impl.ServiceName,
					Host:       impl.ServiceName,
					CA:         impl.CAName,
					Expires:    time.Hour,
				},
			},
		},
		{
			Name: "NilCAOpts",
			Conf: certdepot.BootstrapDepotConfig{
				CAName:      impl.CAName,
				ServiceName: impl.ServiceName,
				ServiceOpts: &certdepot.CertificateOptions{
					CommonName: impl.ServiceName,
					Host:       impl.ServiceName,
					CA:         impl.CAName,
					Expires:    time.Hour,
				},
			},
			Fail: true,
		},
		{
			Name: "NilServiceOpts",
			Conf: certdepot.BootstrapDepotConfig{
				CAName:      impl.CAName,
				ServiceName: impl.ServiceName,
				CAOpts: &certdepot.CertificateOptions{
					CommonName: impl.CAName,
					Expires:    time.Hour,
				},
			},
			Fail: true,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			implDepot := impl.Setup(t, &test.Conf)
			if test.Setup != nil {
				test.Setup(t, implDepot)
			}

			bd, err := certdepot.BootstrapDepot(ctx, implDepot, test.Conf)
			if test.Fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				assert.True(t, bd.Check(depot.CrtTag(impl.CAName)))
				assert.True(t, bd.Check(depot.PrivKeyTag(impl.CAName)))
				assert.True(t, bd.Check(depot.CrtTag(impl.ServiceName)))
				assert.True(t, bd.Check(depot.PrivKeyTag(impl.ServiceName)))
			}

			if test.Test != nil {
				test.Test(t, bd)
			}
			impl.TearDown(t)
		})
	}

	t.Run("UseExisting", func(t *testing.T) {
		const tmpDepotName = "temp_depot"

		assert.NoError(t, os.RemoveAll(tmpDepotName))
		defer func() { assert.NoError(t, os.RemoveAll(tmpDepotName)) }()

		require.NoError(t, os.MkdirAll(tmpDepotName, 0777))

		tempDepot, err := depot.NewFileDepot(tmpDepotName)
		require.NoError(t, err)
		wd := certdepot.MakeDepot(tempDepot, certdepot.Options{})

		conf := certdepot.BootstrapDepotConfig{
			CAName:      impl.CAName,
			ServiceName: impl.ServiceName,
			CAOpts: &certdepot.CertificateOptions{
				CommonName: impl.CAName,
				Expires:    time.Hour,
			},
			ServiceOpts: &certdepot.CertificateOptions{
				CommonName: impl.ServiceName,
				Host:       impl.ServiceName,
				CA:         impl.CAName,
				Expires:    time.Hour,
			},
		}

		dpt, err := certdepot.BootstrapDepot(ctx, wd, conf)
		require.NoError(t, err)

		caCert, err := dpt.Get(depot.CrtTag(impl.CAName))
		require.NoError(t, err)
		caKey, err := dpt.Get(depot.PrivKeyTag(impl.CAName))
		require.NoError(t, err)

		conf = certdepot.BootstrapDepotConfig{
			CAName:      impl.CAName,
			ServiceName: impl.ServiceName,
			CACert:      string(caCert),
			CAKey:       string(caKey),
			CAOpts: &certdepot.CertificateOptions{
				CommonName: impl.CAName,
				Expires:    time.Hour,
			},
			ServiceOpts: &certdepot.CertificateOptions{
				CommonName: impl.ServiceName,
				Host:       impl.ServiceName,
				CA:         impl.CAName,
				Expires:    time.Hour,
			},
		}

		dpt2, err := certdepot.BootstrapDepot(ctx, wd, conf)
		require.NoError(t, err)

		data, err := dpt2.Get(depot.CrtTag(impl.CAName))
		assert.NoError(t, err)
		assert.Equal(t, data, caCert)
		data, err = dpt2.Get(depot.PrivKeyTag(impl.CAName))
		assert.NoError(t, err)
		assert.Equal(t, data, caKey)
	})
}
