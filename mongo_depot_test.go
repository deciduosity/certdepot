package certdepot

import (
	"testing"
	"time"

	"github.com/square/certstrap/depot"
	"github.com/stretchr/testify/suite"
	mgo "gopkg.in/mgo.v2"
)

type MongoDepotTestSuite struct {
	session        *mgo.Session
	collection     *mgo.Collection
	databaseName   string
	collectionName string
	mongoDepot     depot.Depot

	suite.Suite
}

func TestMongoDepot(t *testing.T) {
	s := &MongoDepotTestSuite{}
	suite.Run(t, s)
}

func (s *MongoDepotTestSuite) TearDownTest() {
	err := s.collection.DropCollection()
	if err != nil {
		s.Require().Equal("ns not found", err.Error())
	}
}

func (s *MongoDepotTestSuite) SetupSuite() {
	var err error
	s.session, err = mgo.DialWithTimeout("mongodb://localhost:27017", 2*time.Second)
	s.Require().NoError(err)
	s.session.SetSocketTimeout(time.Hour)
	s.databaseName = "certDepot"
	s.collectionName = "certs"
	s.collection = s.session.DB(s.databaseName).C(s.collectionName)
	s.TearDownTest()
	s.mongoDepot = &mongoCertDepot{
		session:        s.session,
		databaseName:   s.databaseName,
		collectionName: s.collectionName,
		expireAfter:    30 * 24 * time.Hour,
	}
}

func (s *MongoDepotTestSuite) TestPut() {
	name := "bob"

	// put fails with nil data
	s.Error(s.mongoDepot.Put(depot.CrtTag(name), nil))

	// put correctly adds cert data
	beforeTime := time.Now()
	time.Sleep(time.Second)
	certData := []byte("bob's fake certificate")
	s.NoError(s.mongoDepot.Put(depot.CrtTag(name), certData))
	u := &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(string(certData), u.Cert)
	s.Empty(u.PrivateKey)
	s.Empty(u.CertReq)
	s.True(beforeTime.Before(u.TTL))

	// put correctly updates cert data
	beforeTime = time.Now()
	time.Sleep(time.Second)
	certData = []byte("bob's new fake certificate")
	s.NoError(s.mongoDepot.Put(depot.CrtTag(name), certData))
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(string(certData), u.Cert)
	s.Empty(u.PrivateKey)
	s.Empty(u.CertReq)
	s.True(beforeTime.Before(u.TTL))

	// put correctly adds key data
	keyData := []byte("bob's fake private key")
	time.Sleep(time.Second)
	afterTime := time.Now()
	s.NoError(s.mongoDepot.Put(depot.PrivKeyTag(name), keyData))
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(string(certData), u.Cert)
	s.Equal(string(keyData), u.PrivateKey)
	s.Empty(u.CertReq)
	s.Empty(u.CertRevocList)
	s.True(afterTime.After(u.TTL))

	// put correctly updates key data
	keyData = []byte("bob's new fake private key")
	s.NoError(s.mongoDepot.Put(depot.PrivKeyTag(name), keyData))
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(string(certData), u.Cert)
	s.Equal(string(keyData), u.PrivateKey)
	s.Empty(u.CertReq)
	s.Empty(u.CertRevocList)
	s.True(afterTime.After(u.TTL))

	// put correctly adds cert request data
	certReqData := []byte("bob's fake certificate request")
	s.NoError(s.mongoDepot.Put(depot.CsrTag(name), certReqData))
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(string(certData), u.Cert)
	s.Equal(string(keyData), u.PrivateKey)
	s.Equal(string(certReqData), u.CertReq)
	s.Empty(u.CertRevocList)
	s.True(afterTime.After(u.TTL))

	// put correctly updates adds cert request data
	certReqData = []byte("bob's new fake certificate request")
	s.NoError(s.mongoDepot.Put(depot.CsrTag(name), certReqData))
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(string(certData), u.Cert)
	s.Equal(string(keyData), u.PrivateKey)
	s.Equal(string(certReqData), u.CertReq)
	s.Empty(u.CertRevocList)
	s.True(afterTime.After(u.TTL))

	// put correctly adds cert revocation list
	certRevocListData := []byte("bob's fake certificate revocation list")
	s.NoError(s.mongoDepot.Put(depot.CrlTag(name), certRevocListData))
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(string(certData), u.Cert)
	s.Equal(string(keyData), u.PrivateKey)
	s.Equal(string(certReqData), u.CertReq)
	s.Equal(string(certRevocListData), u.CertRevocList)
	s.True(afterTime.After(u.TTL))

	// put correctly updates adds cert revocation list
	certRevocListData = []byte("bob's new fake certificate revocation list")
	s.NoError(s.mongoDepot.Put(depot.CrlTag(name), certRevocListData))
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(string(certData), u.Cert)
	s.Equal(string(keyData), u.PrivateKey)
	s.Equal(string(certReqData), u.CertReq)
	s.Equal(string(certRevocListData), u.CertRevocList)
	s.True(afterTime.After(u.TTL))

}

func (s *MongoDepotTestSuite) TestCheck() {
	name := "alice"
	u := &User{
		ID:  name,
		TTL: time.Now(),
	}
	s.Require().NoError(s.collection.Insert(&User{ID: "bob"}))

	// check returns false when a user does not exist
	s.False(s.mongoDepot.Check(depot.CrtTag(name)))
	s.False(s.mongoDepot.Check(depot.PrivKeyTag(name)))
	s.False(s.mongoDepot.Check(depot.CsrTag(name)))
	s.False(s.mongoDepot.Check(depot.CrlTag(name)))

	// check returns true when a user exists AND the tag data
	s.Require().NoError(s.collection.Insert(u))
	s.False(s.mongoDepot.Check(depot.CrtTag(name)))
	s.False(s.mongoDepot.Check(depot.PrivKeyTag(name)))
	s.False(s.mongoDepot.Check(depot.CsrTag(name)))
	s.False(s.mongoDepot.Check(depot.CrlTag(name)))

	u.Cert = "alice's fake certificate"
	_, err := s.collection.UpsertId(name, u)
	s.Require().NoError(err)
	s.True(s.mongoDepot.Check(depot.CrtTag(name)))
	s.False(s.mongoDepot.Check(depot.PrivKeyTag(name)))
	s.False(s.mongoDepot.Check(depot.CsrTag(name)))
	s.False(s.mongoDepot.Check(depot.CrlTag(name)))

	u.PrivateKey = "alice's fake private key"
	_, err = s.collection.UpsertId(name, u)
	s.Require().NoError(err)
	s.True(s.mongoDepot.Check(depot.CrtTag(name)))
	s.True(s.mongoDepot.Check(depot.PrivKeyTag(name)))
	s.False(s.mongoDepot.Check(depot.CsrTag(name)))
	s.False(s.mongoDepot.Check(depot.CrlTag(name)))

	u.CertReq = "alice's fake certificate request"
	_, err = s.collection.UpsertId(name, u)
	s.Require().NoError(err)
	s.True(s.mongoDepot.Check(depot.CrtTag(name)))
	s.True(s.mongoDepot.Check(depot.PrivKeyTag(name)))
	s.True(s.mongoDepot.Check(depot.CsrTag(name)))
	s.False(s.mongoDepot.Check(depot.CrlTag(name)))

	u.CertRevocList = "alice's fake certificate revocation list"
	_, err = s.collection.UpsertId(name, u)
	s.Require().NoError(err)
	s.True(s.mongoDepot.Check(depot.CrtTag(name)))
	s.True(s.mongoDepot.Check(depot.PrivKeyTag(name)))
	s.True(s.mongoDepot.Check(depot.CsrTag(name)))
	s.True(s.mongoDepot.Check(depot.CrlTag(name)))
}

func (s *MongoDepotTestSuite) TestGet() {
	name := "bob"
	u := &User{
		ID:  name,
		TTL: time.Now(),
	}
	s.Require().NoError(s.collection.Insert(&User{ID: "alice"}))

	// get returns an error when the user does not exist
	data, err := s.mongoDepot.Get(depot.CrtTag(name))
	s.Error(err)
	s.Nil(data)

	// get returns data when user exists AND tag data exists
	s.Require().NoError(s.collection.Insert(u))
	data, err = s.mongoDepot.Get(depot.CrtTag(name))
	s.Error(err)
	s.Nil(data)
	data, err = s.mongoDepot.Get(depot.PrivKeyTag(name))
	s.Error(err)
	s.Nil(data)
	data, err = s.mongoDepot.Get(depot.CsrTag(name))
	s.Error(err)
	s.Nil(data)

	certData := []byte("bob's fake certificate")
	u.Cert = string(certData)
	_, err = s.collection.UpsertId(name, u)
	s.Require().NoError(err)
	data, err = s.mongoDepot.Get(depot.CrtTag(name))
	s.NoError(err)
	s.Equal(certData, data)
	// fails with expired TTL
	u.TTL = time.Time{}
	_, err = s.collection.UpsertId(name, u)
	s.Require().NoError(err)
	data, err = s.mongoDepot.Get(depot.CrtTag(name))
	s.Error(err)
	s.Nil(data)

	keyData := []byte("bob's fake private key")
	u.PrivateKey = string(keyData)
	_, err = s.collection.UpsertId(name, u)
	s.Require().NoError(err)
	data, err = s.mongoDepot.Get(depot.PrivKeyTag(name))
	s.NoError(err)
	s.Equal(keyData, data)

	certReqData := []byte("bob's fake certificate request")
	u.CertReq = string(certReqData)
	_, err = s.collection.UpsertId(name, u)
	s.Require().NoError(err)
	data, err = s.mongoDepot.Get(depot.CsrTag(name))
	s.NoError(err)
	s.Equal(certReqData, data)

	u.TTL = time.Now()
	_, err = s.collection.UpsertId(name, u)
	s.Require().NoError(err)

	certRevocListData := []byte("bob's fake certificate revocation list")
	u.Cert = string(certRevocListData)
	_, err = s.collection.UpsertId(name, u)
	s.Require().NoError(err)
	data, err = s.mongoDepot.Get(depot.CrlTag(name))
	s.NoError(err)
	s.Equal(certRevocListData, data)
	// fails with expired TTL
	u.TTL = time.Time{}
	_, err = s.collection.UpsertId(name, u)
	s.Require().NoError(err)
	data, err = s.mongoDepot.Get(depot.CrlTag(name))
	s.Error(err)
	s.Nil(data)
}

func (s *MongoDepotTestSuite) TestDelete() {
	deleteName := "alice"
	deleteFrom := &User{
		ID:            deleteName,
		Cert:          "alice's fake certificate",
		PrivateKey:    "alice's fake private key",
		CertReq:       "alice's fake certificate request",
		CertRevocList: "alice's fake certificate revocation list",
		TTL:           time.Now(),
	}
	name := "bob"
	data := "bob's data"
	doNotDelete := &User{
		ID:            name,
		Cert:          data,
		PrivateKey:    data,
		CertReq:       data,
		CertRevocList: data,
		TTL:           time.Now(),
	}

	// delete does not return an error when user does not exist
	s.NoError(s.mongoDepot.Delete(depot.CrtTag(deleteName)))
	s.NoError(s.mongoDepot.Delete(depot.PrivKeyTag(deleteName)))
	s.NoError(s.mongoDepot.Delete(depot.CsrTag(deleteName)))

	// delete removes correct data
	s.Require().NoError(s.collection.Insert(deleteFrom))
	s.Require().NoError(s.collection.Insert(doNotDelete))

	s.NoError(s.mongoDepot.Delete(depot.CrtTag(deleteName)))
	u := &User{}
	s.Require().NoError(s.collection.FindId(deleteName).One(u))
	s.Equal(deleteName, u.ID)
	s.Empty(u.Cert)
	s.Equal(deleteFrom.PrivateKey, u.PrivateKey)
	s.Equal(deleteFrom.CertReq, u.CertReq)
	s.Equal(deleteFrom.CertRevocList, u.CertRevocList)
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(data, u.Cert)
	s.Equal(data, u.PrivateKey)
	s.Equal(data, u.CertReq)
	s.Equal(data, u.CertRevocList)

	s.NoError(s.mongoDepot.Delete(depot.PrivKeyTag(deleteName)))
	u = &User{}
	s.Require().NoError(s.collection.FindId(deleteName).One(u))
	s.Equal(deleteName, u.ID)
	s.Empty(u.Cert)
	s.Empty(u.PrivateKey)
	s.Equal(deleteFrom.CertReq, u.CertReq)
	s.Equal(deleteFrom.CertRevocList, u.CertRevocList)
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(data, u.Cert)
	s.Equal(data, u.PrivateKey)
	s.Equal(data, u.CertReq)
	s.Equal(data, u.CertRevocList)

	s.NoError(s.mongoDepot.Delete(depot.CsrTag(deleteName)))
	u = &User{}
	s.Require().NoError(s.collection.FindId(deleteName).One(u))
	s.Equal(deleteName, u.ID)
	s.Empty(u.Cert)
	s.Empty(u.PrivateKey)
	s.Empty(u.CertReq)
	s.Equal(deleteFrom.CertRevocList, u.CertRevocList)
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(data, u.Cert)
	s.Equal(data, u.PrivateKey)
	s.Equal(data, u.CertReq)
	s.Equal(data, u.CertRevocList)

	s.NoError(s.mongoDepot.Delete(depot.CrlTag(deleteName)))
	u = &User{}
	s.Require().NoError(s.collection.FindId(deleteName).One(u))
	s.Equal(deleteName, u.ID)
	s.Empty(u.Cert)
	s.Empty(u.PrivateKey)
	s.Empty(u.CertReq)
	s.Empty(u.CertRevocList)
	u = &User{}
	s.Require().NoError(s.collection.FindId(name).One(u))
	s.Equal(name, u.ID)
	s.Equal(data, u.Cert)
	s.Equal(data, u.PrivateKey)
	s.Equal(data, u.CertReq)
	s.Equal(data, u.CertRevocList)
}
