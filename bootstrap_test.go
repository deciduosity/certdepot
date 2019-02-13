package certdepot

import (
	"os"
	"testing"
	"time"

	"github.com/square/certstrap/depot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mgo "gopkg.in/mgo.v2"
)

func TestBootstrapDepotConfigValidate(t *testing.T) {
	for _, test := range []struct {
		name string
		conf BootstrapDepotConfig
		fail bool
	}{
		{
			name: "ValidFileDepot",
			conf: BootstrapDepotConfig{
				FileDepot:   "depot",
				CAName:      "root",
				ServiceName: "localhost",
				CACert:      []byte("ca cert"),
				CAKey:       []byte("ca key"),
			},
		},
		{
			name: "ValidMgoDepot",
			conf: BootstrapDepotConfig{
				MgoDepot:    &MgoCertDepotOptions{},
				CAName:      "root",
				ServiceName: "localhost",
				CACert:      []byte("ca cert"),
				CAKey:       []byte("ca key"),
			},
		},
		{
			name: "UnsetDepot",
			conf: BootstrapDepotConfig{
				CAName:      "root",
				ServiceName: "localhost",
				CACert:      []byte("ca cert"),
				CAKey:       []byte("ca key"),
			},
			fail: true,
		},
		{
			name: "MoreThanOneDepotSet",
			conf: BootstrapDepotConfig{
				FileDepot:   "depot",
				MgoDepot:    &MgoCertDepotOptions{},
				CAName:      "root",
				ServiceName: "localhost",
				CACert:      []byte("ca cert"),
				CAKey:       []byte("ca key"),
			},
			fail: true,
		},
		{
			name: "NoCANameOrServiceName",
			conf: BootstrapDepotConfig{
				FileDepot: "depot",
				CACert:    []byte("ca cert"),
				CAKey:     []byte("ca key"),
			},
			fail: true,
		},
		{
			name: "NoCAName",
			conf: BootstrapDepotConfig{
				FileDepot:   "depot",
				ServiceName: "localhost",
				CACert:      []byte("ca cert"),
				CAKey:       []byte("ca key"),
			},
			fail: true,
		},
		{
			name: "NoServiceName",
			conf: BootstrapDepotConfig{
				FileDepot: "depot",
				CAName:    "root",
				CACert:    []byte("ca cert"),
				CAKey:     []byte("ca key"),
			},
			fail: true,
		},
		{
			name: "CACertSetCAKeyUnset",
			conf: BootstrapDepotConfig{
				FileDepot:   "depot",
				CAName:      "root",
				ServiceName: "localhost",
				CACert:      []byte("ca cert"),
			},
			fail: true,
		},
		{
			name: "CACertUnsetCAKeySet",
			conf: BootstrapDepotConfig{
				FileDepot:   "depot",
				CAName:      "root",
				ServiceName: "localhost",
				CAKey:       []byte("ca key"),
			},
			fail: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.fail {
				assert.Error(t, test.conf.Validate())
			} else {
				assert.NoError(t, test.conf.Validate())
			}
		})
	}
}

func TestBootstrapDepot(t *testing.T) {
	depotName := "bootstrap_test"
	caName := "test_ca"
	serviceName := "test_service"
	databaseName := "certs"
	session, err := mgo.DialWithTimeout("mongodb://localhost:27017", 2*time.Second)
	require.NoError(t, err)
	tempDepot, err := depot.NewFileDepot("temp_depot")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, os.RemoveAll(depotName))
		assert.NoError(t, session.DB(databaseName).DropDatabase())
		assert.NoError(t, os.RemoveAll("temp_depot"))
	}()

	opts := CertificateOptions{
		CommonName: caName,
		Expires:    time.Hour,
	}
	require.NoError(t, opts.Init(tempDepot))
	caCert, err := tempDepot.Get(depot.CrtTag(caName))
	require.NoError(t, err)
	caKey, err := tempDepot.Get(depot.PrivKeyTag(caName))
	require.NoError(t, err)

	for _, impl := range []struct {
		name     string
		setup    func(*BootstrapDepotConfig) depot.Depot
		tearDown func()
	}{
		{
			name: "FileDepot",
			setup: func(conf *BootstrapDepotConfig) depot.Depot {
				conf.FileDepot = depotName

				d, err := depot.NewFileDepot(depotName)
				require.NoError(t, err)
				return d
			},
			tearDown: func() {
				require.NoError(t, os.RemoveAll(depotName))
			},
		},
		{
			name: "MgoDepot",
			setup: func(conf *BootstrapDepotConfig) depot.Depot {
				conf.MgoDepot = &MgoCertDepotOptions{
					DatabaseName:   databaseName,
					CollectionName: depotName,
				}

				d, err := NewMgoCertDepot(*conf.MgoDepot)
				require.NoError(t, err)
				return d
			},
			tearDown: func() {
				require.NoError(t, session.DB(databaseName).C(depotName).DropCollection())
			},
		},
	} {
		t.Run(impl.name, func(t *testing.T) {
			for _, test := range []struct {
				name  string
				conf  BootstrapDepotConfig
				setup func(depot.Depot)
				test  func(depot.Depot)
			}{
				{
					name: "ExistingCertsInDepot",
					conf: BootstrapDepotConfig{
						CAName:      caName,
						ServiceName: serviceName,
					},
					setup: func(d depot.Depot) {
						assert.NoError(t, d.Put(depot.CrtTag(caName), []byte("fake ca cert")))
						assert.NoError(t, d.Put(depot.PrivKeyTag(caName), []byte("fake ca key")))
						assert.NoError(t, d.Put(depot.CrtTag(serviceName), []byte("fake service cert")))
						assert.NoError(t, d.Put(depot.PrivKeyTag(serviceName), []byte("fake service key")))
					},
					test: func(d depot.Depot) {
						data, err := d.Get(depot.CrtTag(caName))
						assert.NoError(t, err)
						assert.Equal(t, data, []byte("fake ca cert"))
						data, err = d.Get(depot.PrivKeyTag(caName))
						assert.NoError(t, err)
						assert.Equal(t, data, []byte("fake ca key"))
						data, err = d.Get(depot.CrtTag(serviceName))
						assert.NoError(t, err)
						assert.Equal(t, data, []byte("fake service cert"))
						data, err = d.Get(depot.PrivKeyTag(serviceName))
						assert.NoError(t, err)
						assert.Equal(t, data, []byte("fake service key"))
					},
				},
				{
					name: "ExistingCAPassedIn",
					conf: BootstrapDepotConfig{
						CAName:      caName,
						ServiceName: serviceName,
						CACert:      caCert,
						CAKey:       caKey,
						ServiceOpts: CertificateOptions{
							CommonName: serviceName,
							Host:       serviceName,
							CA:         caName,
							Expires:    time.Hour,
						},
					},
					test: func(d depot.Depot) {
						data, err := d.Get(depot.CrtTag(caName))
						assert.NoError(t, err)
						assert.Equal(t, data, caCert)
						data, err = d.Get(depot.PrivKeyTag(caName))
						assert.NoError(t, err)
						assert.Equal(t, data, caKey)
					},
				},
				{
					name: "CertCreation",
					conf: BootstrapDepotConfig{
						CAName:      caName,
						ServiceName: serviceName,
						CAOpts: CertificateOptions{
							CommonName: caName,
							Expires:    time.Hour,
						},
						ServiceOpts: CertificateOptions{
							CommonName: serviceName,
							Host:       serviceName,
							CA:         caName,
							Expires:    time.Hour,
						},
					},
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					implDepot := impl.setup(&test.conf)
					defer impl.tearDown()
					if test.setup != nil {
						test.setup(implDepot)
					}
					bootstrapDepot, err := BootstrapDepot(test.conf)
					require.NoError(t, err)

					assert.True(t, bootstrapDepot.Check(depot.CrtTag(caName)))
					assert.True(t, bootstrapDepot.Check(depot.PrivKeyTag(caName)))
					assert.True(t, bootstrapDepot.Check(depot.CrtTag(serviceName)))
					assert.True(t, bootstrapDepot.Check(depot.PrivKeyTag(serviceName)))

					if test.test != nil {
						test.test(bootstrapDepot)
					}
				})
			}
		})
	}
}
