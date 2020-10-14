package certdepot

import (
	"context"

	"github.com/deciduosity/grip"
	"github.com/pkg/errors"
	"github.com/square/certstrap/depot"
)

// BootstrapDepotConfig contains options for BootstrapDepot. Must provide
// either the name of the FileDepot or the MongoDepot options, not both or
// neither.
type BootstrapDepotConfig struct {
	// CA certificate, this is optional unless CAKey is not empty, in
	// which case a CA certificate must also be provided.
	CACert string `bson:"ca_cert" json:"ca_cert" yaml:"ca_cert"`
	// CA key, this is optional unless CACert is not empty, in which case
	// a CA key must also be provided.
	CAKey string `bson:"ca_key" json:"ca_key" yaml:"ca_key"`
	// Common name of the CA (required).
	CAName string `bson:"ca_name" json:"ca_name" yaml:"ca_name"`
	// Common name of the service (required).
	ServiceName string `bson:"service_name" json:"service_name" yaml:"service_name"`
	// Options to initialize a CA. This is optional and only used if there
	// is no existing `CAName` in the depot and `CACert` is empty.
	// `CAOpts.CommonName` must equal `CAName`.
	CAOpts *CertificateOptions `bson:"ca_opts,omitempty" json:"ca_opts,omitempty" yaml:"ca_opts,omitempty"`
	// Options to create a service certificate. This is optional and only
	// used if there is no existing `ServiceName` in the depot.
	// `ServiceOpts.CommonName` must equal `ServiceName`.
	// `ServiceOpts.CA` must equal `CAName`.
	ServiceOpts *CertificateOptions `bson:"service_opts,omitempty" json:"service_opts,omitempty" yaml:"service_opts,omitempty"`
}

// Validate ensures that the BootstrapDepotConfig is configured correctly.
func (c *BootstrapDepotConfig) Validate() error {
	catcher := grip.NewBasicCatcher()

	catcher.NewWhen(c.CAName == "" || c.ServiceName == "",
		"must specify the name of the CA and service")
	catcher.NewWhen((c.CACert != "" && c.CAKey == "") || (c.CACert == "" && c.CAKey != ""),
		"must provide both cert and key file if want to bootstrap with existing CA")
	catcher.NewWhen(c.CAOpts != nil && c.CAOpts.CommonName != c.CAName,
		"CAName and CAOpts.CommonName must be the same")
	catcher.NewWhen(c.ServiceOpts != nil && c.ServiceOpts.CommonName != c.ServiceName,
		"ServiceName and ServiceOpts.CommonName must be the same")
	catcher.NewWhen(c.ServiceOpts != nil && c.ServiceOpts.CA != c.CAName,
		"CAName and ServiceOpts.CA must be the same")

	return catcher.Resolve()
}

// BootstrapDepot creates a certificate depot with a CA and service
// certificate.
func BootstrapDepot(ctx context.Context, d Depot, conf BootstrapDepotConfig) (Depot, error) {
	if conf.CACert != "" {
		if err := addCert(d, conf); err != nil {
			return nil, errors.Wrap(err, "problem adding a ca cert")
		}
	}
	if !depot.CheckCertificate(d, conf.CAName) {
		if err := createCA(d, conf); err != nil {
			return nil, errors.Wrap(err, "problem during certificate creation")
		}
	}
	if !depot.CheckCertificate(d, conf.ServiceName) {
		if err := createServerCert(d, conf); err != nil {
			return nil, errors.Wrap(err, "problem checking the service certificate")
		}
	}

	return d, nil
}

func addCert(d Depot, conf BootstrapDepotConfig) error {
	if cert, err := d.Get(depot.CrtTag(conf.CAName)); err == nil {
		if string(cert) == conf.CACert {
			return nil
		}
	}

	if err := d.Put(depot.CrtTag(conf.CAName), []byte(conf.CACert)); err != nil {
		return errors.Wrap(err, "problem adding CA cert to depot")
	}

	if err := d.Put(depot.PrivKeyTag(conf.CAName), []byte(conf.CAKey)); err != nil {
		return errors.Wrap(err, "problem adding CA key to depot")
	}

	return nil
}

func createCA(d Depot, conf BootstrapDepotConfig) error {
	if conf.CAOpts == nil {
		return errors.New("cannot create a new CA with nil CA options")
	}
	if err := conf.CAOpts.Init(d); err != nil {
		return errors.Wrap(err, "problem initializing the ca")
	}
	if err := createServerCert(d, conf); err != nil {
		return errors.Wrap(err, "problem creating the server cert")
	}

	return nil
}

func createServerCert(d Depot, conf BootstrapDepotConfig) error {
	if conf.ServiceOpts == nil {
		return errors.New("cannot create a new server cert with nil service options")
	}
	if err := conf.ServiceOpts.CertRequest(d); err != nil {
		return errors.Wrap(err, "problem creating service cert request")
	}
	if err := conf.ServiceOpts.Sign(d); err != nil {
		return errors.Wrap(err, "problem signing service key")
	}

	return nil
}
