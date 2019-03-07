package certdepot

import (
	"time"

	"github.com/mongodb/anser/bsonutil"
	"github.com/mongodb/grip"
	"github.com/mongodb/grip/message"
	"github.com/pkg/errors"
	"github.com/square/certstrap/depot"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type User struct {
	ID            string    `bson:"_id"`
	Cert          string    `bson:"cert"`
	PrivateKey    string    `bson:"private_key"`
	CertReq       string    `bson:"cert_req"`
	CertRevocList string    `bson:"cert_revoc_list"`
	TTL           time.Time `bson:"ttl"`
}

var (
	userIDKey            = bsonutil.MustHaveTag(User{}, "ID")
	userCertKey          = bsonutil.MustHaveTag(User{}, "Cert")
	userPrivateKeyKey    = bsonutil.MustHaveTag(User{}, "PrivateKey")
	userCertReqKey       = bsonutil.MustHaveTag(User{}, "CertReq")
	userCertRevocListKey = bsonutil.MustHaveTag(User{}, "CertRevocList")
	userTTLKey           = bsonutil.MustHaveTag(User{}, "TTL")
)

type mongoCertDepot struct {
	session        *mgo.Session
	databaseName   string
	collectionName string
	expireAfter    time.Duration
}

type MgoCertDepotOptions struct {
	MongoDBURI           string        `bson:"mongodb_uri" json:"mongodb_uri" yaml:"mongodb_uri"`
	DatabaseName         string        `bson:"db_name" json:"db_name" yaml:"db_name"`
	CollectionName       string        `bson:"coll_name" json:"coll_name" yaml:"coll_name"`
	MongoDBDialTimeout   time.Duration `bson:"dial_timeout,omitempty" json:"dial_timeout,omitempty" yaml:"dial_timeout,omitempty"`
	MongoDBSocketTimeout time.Duration `bson:"socket_timeout,omitempty" json:"socket_timeout,omitempty" yaml:"socket_timeout,omitempty"`
	ExpireAfter          time.Duration `bson:"expire_after,omitempty" json:"expire_after,omitempty" yaml:"expire_after,omitempty"`
}

func (opts *MgoCertDepotOptions) IsZero() bool {
	if opts.DatabaseName == "" && opts.CollectionName == "" {
		return true
	}

	return false
}

// Create a new cert depot in the specified MongoDB.
func NewMgoCertDepot(opts MgoCertDepotOptions) (depot.Depot, error) {
	return newMgoCertDepot(nil, opts)
}

// Create a new cert depot in the specified MongoDB, using an existing session.
func NewMgoCertDepotWithSession(s *mgo.Session, opts MgoCertDepotOptions) (depot.Depot, error) {
	return newMgoCertDepot(s, opts)
}

func newMgoCertDepot(s *mgo.Session, opts MgoCertDepotOptions) (depot.Depot, error) {
	if err := opts.validate(); err != nil {
		return nil, errors.Wrap(err, "invalid options!")
	}

	if s == nil {
		var err error
		s, err = mgo.DialWithTimeout(opts.MongoDBURI, opts.MongoDBDialTimeout)
		if err != nil {
			return nil, errors.Wrapf(err, "could not connect to db %s", opts.MongoDBURI)
		}
		s.SetSocketTimeout(opts.MongoDBSocketTimeout)
	}

	return &mongoCertDepot{
		session:        s,
		databaseName:   opts.DatabaseName,
		collectionName: opts.CollectionName,
		expireAfter:    opts.ExpireAfter,
	}, nil
}

func (opts *MgoCertDepotOptions) validate() error {
	if opts.MongoDBURI == "" {
		opts.MongoDBURI = "mongodb://localhost:27017"
	}
	if opts.MongoDBDialTimeout <= 0 {
		opts.MongoDBDialTimeout = 2 * time.Second
	}
	if opts.MongoDBSocketTimeout <= 0 {
		opts.MongoDBSocketTimeout = time.Minute
	}
	if opts.DatabaseName == "" {
		opts.DatabaseName = "certDepot"
	}
	if opts.CollectionName == "" {
		opts.CollectionName = "certs"
	}
	if opts.ExpireAfter <= 0 {
		opts.ExpireAfter = 30 * 24 * time.Hour
	}

	return nil
}

// Put inserts the data into the document specified by the tag.
func (m *mongoCertDepot) Put(tag *depot.Tag, data []byte) error {
	if data == nil {
		return errors.New("data is nil")
	}

	name, key := getNameAndKey(tag)
	session := m.session.Clone()
	defer session.Close()

	update := bson.M{"$set": bson.M{key: string(data)}}
	if key == userCertKey {
		update["$set"].(bson.M)[userTTLKey] = time.Now()
	}
	changeInfo, err := session.DB(m.databaseName).C(m.collectionName).UpsertId(name, update)
	if err != nil {
		return errors.Wrap(err, "problem adding data to the database")
	}
	grip.Debug(message.Fields{
		"db":     m.databaseName,
		"coll":   m.collectionName,
		"id":     name,
		"change": changeInfo,
		"op":     "put",
	})

	return nil
}

// Check returns whether the user and data specified by the tag exists.
func (m *mongoCertDepot) Check(tag *depot.Tag) bool {
	name, key := getNameAndKey(tag)
	session := m.session.Clone()
	defer session.Close()

	u := &User{}
	err := session.DB(m.databaseName).C(m.collectionName).FindId(name).One(u)
	grip.WarningWhen(errNotNotFound(err), message.Fields{
		"db":   m.databaseName,
		"coll": m.collectionName,
		"id":   name,
		"err":  err,
		"op":   "check",
	})

	switch key {
	case userCertKey:
		return u.Cert != ""
	case userPrivateKeyKey:
		return u.PrivateKey != ""
	case userCertReqKey:
		return u.CertReq != ""
	case userCertRevocListKey:
		return u.CertRevocList != ""
	default:
		return false
	}
}

// Get reads the data for the user specified by tag. Returns an error if the
// user does not exist, if the TTL has expired (for certs), or if the data is
// empty.
func (m *mongoCertDepot) Get(tag *depot.Tag) ([]byte, error) {
	name, key := getNameAndKey(tag)
	session := m.session.Clone()
	defer session.Close()

	u := &User{}
	err := session.DB(m.databaseName).C(m.collectionName).FindId(name).One(u)
	if err == mgo.ErrNotFound {
		return nil, errors.Errorf("could not find %s in the database", name)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "problem looking up %s in the database", name)
	}

	var data []byte
	switch key {
	case userCertKey:
		data = []byte(u.Cert)
		if len(data) > 0 && time.Since(u.TTL) > m.expireAfter {
			return nil, errors.Errorf("certificate for %s has expired!", name)
		}
	case userPrivateKeyKey:
		data = []byte(u.PrivateKey)
	case userCertReqKey:
		data = []byte(u.CertReq)
	case userCertRevocListKey:
		data = []byte(u.CertRevocList)
		if len(data) > 0 && time.Since(u.TTL) > m.expireAfter {
			return nil, errors.Errorf("certificate revocation list for %s has expired!", name)
		}
	}

	if len(data) == 0 {
		return nil, errors.New("no data available!")
	}
	return data, nil
}

// Delete removes the data from a user specified by the tag.
func (m *mongoCertDepot) Delete(tag *depot.Tag) error {
	name, key := getNameAndKey(tag)
	session := m.session.Clone()
	defer session.Close()

	update := bson.M{"$unset": bson.M{key: ""}}
	err := m.session.DB(m.databaseName).C(m.collectionName).UpdateId(name, update)
	if errNotNotFound(err) {
		return errors.Wrapf(err, "problem deleting %s.%s from the database", name, key)
	}

	return nil
}

func errNotNotFound(err error) bool {
	return err != nil && err != mgo.ErrNotFound
}

func getNameAndKey(tag *depot.Tag) (string, string) {
	if name := depot.GetNameFromCrtTag(tag); name != "" {
		return name, userCertKey
	}
	if name := depot.GetNameFromPrivKeyTag(tag); name != "" {
		return name, userPrivateKeyKey
	}
	if name := depot.GetNameFromCsrTag(tag); name != "" {
		return name, userCertReqKey
	}
	if name := depot.GetNameFromCrlTag(tag); name != "" {
		return name, userCertRevocListKey
	}
	return "", ""
}
