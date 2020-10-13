package certdepot

import (
	"time"

	"github.com/square/certstrap/depot"
)

// Depot is a superset wrapper around certrstap's depot.Depot interface so users only
// need to vendor certdepot.
type Depot interface {
	depot.Depot
	Save(string, *Credentials) error
	Find(string) (*Credentials, error)
	Generate(string) (*Credentials, error)
}

type ExpirationManager interface {
	depot.Depot
	PutTTL(string, time.Time) error
	GetTTL(string) (time.Time, error)
	FindExpiresBefore(time.Time) ([]User, error)
	DeleteExpiresBefore(time.Time) error
}

// DepotOptions capture default options used during certificate
// generation and creation used by depots.
type Options struct {
	CA                string        `bson:"ca" json:"ca" yaml:"ca"`
	DefaultExpiration time.Duration `bson:"default_expiration" json:"default_expiration" yaml:"default_expiration"`
}

// User stores information for a user in a database-backed certificate
// depot.
type User struct {
	ID            string    `json:"id" bson:"_id" db:"id"`
	Cert          string    `json:"cert" bson:"cert" db:"cert"`
	PrivateKey    string    `json:"private_key" bson:"private_key" db:"private_key"`
	CertReq       string    `json:"cert_req" bson:"cert_req" db:"cert_req"`
	CertRevocList string    `json:"cert_revoc_list" bson:"cert_revoc_list" db:"cert_revoc_list"`
	TTL           time.Time `json:"ttl" bson:"ttl,omitempty" db:"ttl"`
}
