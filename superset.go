package certdepot

import (
	"time"

	"github.com/cdr/grip"
	"github.com/pkg/errors"
	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
)

type depotImpl struct {
	depot.Depot
	opts Options
}

// MakeDepot wraps a depot.Depot implementation (or an expiration
// manager, as needed,) in a certdepot.Depot implementation, as the
// extensions to the local interface can be implemented in terms of
// the external interface.
func MakeDepot(d depot.Depot, opts Options) Depot {
	out := &depotImpl{Depot: d, opts: opts}
	if em, ok := d.(ExpirationManager); ok {
		return &expMgr{
			depotImpl: out,
			em:        em,
		}
	}

	return out
}

type expMgr struct {
	*depotImpl
	em ExpirationManager
}

func (em *expMgr) PutTTL(name string, exp time.Time) error { return em.em.PutTTL(name, exp) }

func (em *expMgr) GetTTL(name string) (time.Time, error) { return em.em.GetTTL(name) }

func (em *expMgr) FindExpiresBefore(cutoff time.Time) ([]User, error) {
	return em.em.FindExpiresBefore(cutoff)
}

func (em *expMgr) DeleteExpiresBefore(cutoff time.Time) error {
	return em.em.DeleteExpiresBefore(cutoff)
}

func deleteIfExists(dpt depot.Depot, tags ...*depot.Tag) error {
	catcher := grip.NewBasicCatcher()
	for _, tag := range tags {
		if dpt.Check(tag) {
			catcher.Add(dpt.Delete(tag))
		}
	}
	return catcher.Resolve()
}

func (dpt *depotImpl) Save(name string, creds *Credentials) error {
	if err := deleteIfExists(dpt, CsrTag(name), PrivKeyTag(name), CrtTag(name)); err != nil {
		return errors.Wrap(err, "problem deleting existing credentials")
	}

	if err := dpt.Put(PrivKeyTag(name), creds.Key); err != nil {
		return errors.Wrap(err, "problem saving key")
	}

	if err := dpt.Put(CrtTag(name), creds.Cert); err != nil {
		return errors.Wrap(err, "problem saving certificate")
	}

	crt, err := pkix.NewCertificateFromPEM(creds.Cert)
	if err != nil {
		return errors.Wrap(err, "could not get certificate from PEM bytes")
	}

	if emd, ok := dpt.Depot.(ExpirationManager); ok {
		rawCrt, err := crt.GetRawCertificate()
		if err != nil {
			return errors.Wrap(err, "could not get x509 certificate")
		}

		if err := emd.PutTTL(name, rawCrt.NotAfter); err != nil {
			return errors.Wrap(err, "could not put expiration on credentials")
		}
	}

	return nil
}

func (dpt *depotImpl) Generate(name string) (*Credentials, error) {
	opts := CertificateOptions{
		CA:         dpt.opts.CA,
		CommonName: name,
		Host:       name,
		Expires:    dpt.opts.DefaultExpiration,
	}

	pemCACrt, err := dpt.Get(CrtTag(dpt.opts.CA))
	if err != nil {
		return nil, errors.Wrap(err, "problem getting CA certificate")
	}

	_, key, err := opts.CertRequestInMemory()
	if err != nil {
		return nil, errors.Wrap(err, "problem making certificate request and key")
	}

	pemKey, err := key.ExportPrivate()
	if err != nil {
		return nil, errors.Wrap(err, "problem exporting key")
	}

	crt, err := opts.SignInMemory(dpt)
	if err != nil {
		return nil, errors.Wrap(err, "problem signing certificate request")
	}

	pemCrt, err := crt.Export()
	if err != nil {
		return nil, errors.Wrap(err, "problem exporting certificate")
	}

	creds, err := NewCredentials(pemCACrt, pemCrt, pemKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not create credentials")
	}
	creds.ServerName = name

	return creds, nil
}

func (dpt *depotImpl) Find(name string) (*Credentials, error) {
	caCrt, err := dpt.Get(CrtTag(dpt.opts.CA))
	if err != nil {
		return nil, errors.Wrap(err, "problem getting CA certificate")
	}

	crt, err := dpt.Get(CrtTag(name))
	if err != nil {
		return nil, errors.Wrap(err, "problem getting certificate")
	}

	key, err := dpt.Get(PrivKeyTag(name))
	if err != nil {
		return nil, errors.Wrap(err, "problem getting key")
	}

	creds, err := NewCredentials(caCrt, crt, key)
	if err != nil {
		return nil, errors.Wrap(err, "could not create credentials")
	}
	creds.ServerName = name

	return creds, nil
}
