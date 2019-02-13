package certdepot

import (
	"github.com/pkg/errors"
	"github.com/square/certstrap/depot"
)

type BootstrapDepotConfig struct {
	FileDepot   string               `bson:"file_depot" json:"file_depot" yaml:"file_depot"`
	MgoDepot    *MgoCertDepotOptions `bson:"mgo_depot" json:"mgo_depot" yaml:"mgo_depot"`
	CACert      []byte               `bson:"ca_cert" json:"ca_cert" yaml:"ca_cert"`
	CAKey       []byte               `bson:"ca_key" json:"ca_key" yaml:"ca_key"`
	CAName      string               `bson:"ca_name" json:"ca_name" yaml:"ca_name"`
	ServiceName string               `bson:"service_name" json:"service_name" yaml:"service_name"`
	CAOpts      CertificateOptions   `bson:"ca_opts" json:"ca_opts" yaml:"ca_opts"`
	ServiceOpts CertificateOptions   `bson:"service_opts" json:"service_opts" yaml:"service_opts"`
}

func (c *BootstrapDepotConfig) Validate() error {
	if (c.FileDepot != "" && c.MgoDepot != nil) || (c.FileDepot == "" && c.MgoDepot == nil) {
		return errors.New("cannot set contradictory depot types")
	}
	if c.CAName == "" || c.ServiceName == "" {
		return errors.New("must the name of the CA and service!")
	}
	if (c.CACert != nil && c.CAKey == nil) || (c.CACert == nil && c.CAKey != nil) {
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

	if conf.CACert != nil {
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
	} else if conf.MgoDepot != nil {
		d, err = NewMgoCertDepot(*conf.MgoDepot)
		if err != nil {
			return nil, err
		}
	}

	return d, nil
}

func addCert(d depot.Depot, conf BootstrapDepotConfig) error {
	if err := d.Put(depot.CrtTag(conf.CAName), conf.CACert); err != nil {
		return errors.Wrap(err, "problem adding CA cert to depot")
	}

	if err := d.Put(depot.PrivKeyTag(conf.CAName), conf.CAKey); err != nil {
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
