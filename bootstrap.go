package certdepot

import (
	"github.com/pkg/errors"
	"github.com/square/certstrap/depot"
)

type BootstrapDepotConfig struct {
	FileDepot   string              `bson:"file_depot,omitempty" json:"file_depot,omitempty" yaml:"file_depot,omitempty"`
	MgoDepot    MgoCertDepotOptions `bson:"mgo_depot,omitempty" json:"mgo_depot,omitempty" yaml:"mgo_depot,omitempty"`
	CACert      string              `bson:"ca_cert" json:"ca_cert" yaml:"ca_cert"`
	CAKey       string              `bson:"ca_key" json:"ca_key" yaml:"ca_key"`
	CAName      string              `bson:"ca_name" json:"ca_name" yaml:"ca_name"`
	ServiceName string              `bson:"service_name" json:"service_name" yaml:"service_name"`
	CAOpts      CertificateOptions  `bson:"ca_opts,omitempty" json:"ca_opts,omitempty" yaml:"ca_opts,omitempty"`
	ServiceOpts CertificateOptions  `bson:"service_opts,omitempty" json:"service_opts,omitempty" yaml:"service_opts,omitempty"`
}

func (c *BootstrapDepotConfig) Validate() error {
	if c.FileDepot != "" && !c.MgoDepot.IsZero() {
		return errors.New("cannot specify more than one depot configuration")
	}

	if c.FileDepot == "" && c.MgoDepot.IsZero() {
		return errors.New("must specify one depot configuration")
	}

	if c.CAName == "" || c.ServiceName == "" {
		return errors.New("must the name of the CA and service!")
	}

	if (c.CACert != "" && c.CAKey == "") || (c.CACert == "" && c.CAKey != "") {
		return errors.New("must provide both cert and key file if want to bootstrap with existing CA")
	}

	return nil
}

func BootstrapDepot(conf BootstrapDepotConfig) (depot.Depot, error) {
	if err := conf.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid configuration")
	}

	d, err := createDepot(conf)
	if err != nil {
		return nil, errors.Wrap(err, "problem creating depot")
	}

	if conf.CACert != "" {
		if err = addCert(d, conf); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	if !depot.CheckCertificate(d, conf.CAName) {
		if err = createCA(d, conf); err != nil {
			return nil, errors.WithStack(err)
		}
	} else if !depot.CheckCertificate(d, conf.ServiceName) {
		if err = createServerCert(d, conf); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	return d, nil
}

func createDepot(conf BootstrapDepotConfig) (depot.Depot, error) {
	var d depot.Depot
	var err error

	if conf.FileDepot != "" {
		d, err = depot.NewFileDepot(conf.FileDepot)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	} else if !conf.MgoDepot.IsZero() {
		d, err = NewMgoCertDepot(conf.MgoDepot)
		if err != nil {
			return nil, err
		}
	}

	return d, nil
}

func addCert(d depot.Depot, conf BootstrapDepotConfig) error {
	if err := d.Put(depot.CrtTag(conf.CAName), []byte(conf.CACert)); err != nil {
		return errors.Wrap(err, "problem adding CA cert to depot")
	}

	if err := d.Put(depot.PrivKeyTag(conf.CAName), []byte(conf.CAKey)); err != nil {
		return errors.Wrap(err, "problem adding CA key to depot")
	}

	return nil
}

func createCA(d depot.Depot, conf BootstrapDepotConfig) error {
	if err := conf.CAOpts.Init(d); err != nil {
		return err
	}
	if err := createServerCert(d, conf); err != nil {
		return err
	}

	return nil
}

func createServerCert(d depot.Depot, conf BootstrapDepotConfig) error {
	if err := conf.ServiceOpts.CertRequest(d); err != nil {
		return err
	}
	if err := conf.ServiceOpts.Sign(d); err != nil {
		return err
	}

	return nil
}
