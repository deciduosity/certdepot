package mdepot

import (
	"context"
	"testing"
	"time"

	"github.com/deciduosity/certdepot"
	"github.com/deciduosity/certdepot/testutil"
	"github.com/square/certstrap/depot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestDepot(t *testing.T) {
	var data []byte

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client, err := mongo.Connect(connctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	require.NoError(t, err)

	const (
		databaseName   = "certdb"
		collectionName = "depot"
	)

	impl := testutil.DepotCase{
		Name: "MongoDB",
		Setup: func() certdepot.Depot {
			return certdepot.MakeDepot(&mongoDepot{
				ctx:            ctx,
				client:         client,
				databaseName:   databaseName,
				collectionName: collectionName,
			}, certdepot.Options{})
		},
		Check: func(t *testing.T, tag *depot.Tag, data []byte) {
			var name, key string
			name, key, err = getNameAndKey(tag)
			require.NoError(t, err)

			u := &certdepot.User{}
			coll := client.Database(databaseName).Collection(collectionName)
			require.NoError(t, coll.FindOne(ctx, bson.M{userIDKey: name}).Decode(u))
			assert.Equal(t, name, u.ID)

			var value string
			switch key {
			case userCertKey:
				value = u.Cert
			case userPrivateKeyKey:
				value = u.PrivateKey
			case userCertReqKey:
				value = u.CertReq
			case userCertRevocListKey:
				value = u.CertRevocList
			}
			assert.Equal(t, string(data), value)
		},
		Cleanup: func() {
			require.NoError(t, client.Database(databaseName).Collection(collectionName).Drop(ctx))
		},
		Tests: []testutil.DepotTest{
			{
				Name: "PutUpdates",
				Test: func(t *testing.T, d certdepot.Depot) {
					coll := client.Database(databaseName).Collection(collectionName)
					const name = "bob"
					user := &certdepot.User{
						ID:            name,
						Cert:          "cert",
						PrivateKey:    "key",
						CertReq:       "certReq",
						CertRevocList: "certRevocList",
					}
					_, err = coll.InsertOne(ctx, user)
					require.NoError(t, err)
					time.Sleep(time.Second)

					certData := []byte("bob's new fake certificate")
					assert.NoError(t, d.Put(depot.CrtTag(name), certData))
					u := &certdepot.User{}
					require.NoError(t, coll.FindOne(ctx, bson.M{userIDKey: name}).Decode(u))
					assert.Equal(t, name, u.ID)
					assert.Equal(t, string(certData), u.Cert)
					assert.Equal(t, user.PrivateKey, u.PrivateKey)
					assert.Equal(t, user.CertReq, u.CertReq)
					assert.Equal(t, user.CertRevocList, u.CertRevocList)

					keyData := []byte("bob's new fake private key")
					assert.NoError(t, d.Put(depot.PrivKeyTag(name), keyData))
					u = &certdepot.User{}
					require.NoError(t, coll.FindOne(ctx, bson.M{userIDKey: name}).Decode(u))
					assert.Equal(t, name, u.ID)
					assert.Equal(t, string(certData), u.Cert)
					assert.Equal(t, string(keyData), u.PrivateKey)
					assert.Equal(t, user.CertReq, u.CertReq)
					assert.Equal(t, user.CertRevocList, u.CertRevocList)

					certReqData := []byte("bob's new fake certificate request")
					assert.NoError(t, d.Put(depot.CsrTag(name), certReqData))
					u = &certdepot.User{}
					require.NoError(t, coll.FindOne(ctx, bson.M{userIDKey: name}).Decode(u))
					assert.Equal(t, name, u.ID)
					assert.Equal(t, string(certData), u.Cert)
					assert.Equal(t, string(keyData), u.PrivateKey)
					assert.Equal(t, string(certReqData), u.CertReq)
					assert.Equal(t, user.CertRevocList, u.CertRevocList)

					certRevocListData := []byte("bob's new fake certificate revocation list")
					assert.NoError(t, d.Put(depot.CrlTag(name), certRevocListData))
					u = &certdepot.User{}
					require.NoError(t, coll.FindOne(ctx, bson.M{userIDKey: name}).Decode(u))
					assert.Equal(t, name, u.ID)
					assert.Equal(t, string(certData), u.Cert)
					assert.Equal(t, string(keyData), u.PrivateKey)
					assert.Equal(t, string(certReqData), u.CertReq)
					assert.Equal(t, string(certRevocListData), u.CertRevocList)
				},
			},
			{
				Name: "CheckReturnsFalseOnExistingUserWithNoData",
				Test: func(t *testing.T, d certdepot.Depot) {
					const name = "alice"
					u := &certdepot.User{
						ID: name,
					}
					_, err = client.Database(databaseName).Collection(collectionName).InsertOne(ctx, u)
					require.NoError(t, err)

					assert.False(t, d.Check(depot.CrtTag(name)))
					assert.False(t, d.Check(depot.PrivKeyTag(name)))
					assert.False(t, d.Check(depot.CsrTag(name)))
					assert.False(t, d.Check(depot.CrlTag(name)))
				},
			},
			{
				Name: "GetFailsOnExistingUserWithNoData",
				Test: func(t *testing.T, d certdepot.Depot) {
					const name = "bob"
					u := &certdepot.User{
						ID: name,
					}
					_, err = client.Database(databaseName).Collection(collectionName).InsertOne(ctx, u)
					require.NoError(t, err)

					data, err = d.Get(depot.CrtTag(name))
					assert.Error(t, err)
					assert.Nil(t, data)

					data, err = d.Get(depot.PrivKeyTag(name))
					assert.Error(t, err)
					assert.Nil(t, data)

					data, err = d.Get(depot.CsrTag(name))
					assert.Error(t, err)
					assert.Nil(t, data)

					data, err = d.Get(depot.CrlTag(name))
					assert.Error(t, err)
					assert.Nil(t, data)
				},
			},
			{
				Name: "DeleteWhenDNE",
				Test: func(t *testing.T, d certdepot.Depot) {
					const name = "bob"

					assert.NoError(t, d.Delete(depot.CrtTag(name)))
					assert.NoError(t, d.Delete(depot.PrivKeyTag(name)))
					assert.NoError(t, d.Delete(depot.CsrTag(name)))
					assert.NoError(t, d.Delete(depot.CrlTag(name)))
				},
			},
		},
	}

	t.Run(impl.Name, func(t *testing.T) { impl.Run(ctx, t) })
}

func TestBootstrap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client, err := mongo.Connect(connctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	require.NoError(t, err)

	databaseName := "certs"
	depotName := "bootstrap_test"

	defer func() {
		assert.NoError(t, client.Database(databaseName).Drop(ctx))
	}()

	impl := testutil.BootstrapSuite{
		Name: "MongoDepot",
		Setup: func(t *testing.T, conf *certdepot.BootstrapDepotConfig) certdepot.Depot {
			opt := &MongoDBOptions{
				DatabaseName:   databaseName,
				CollectionName: depotName,
			}

			d, err := NewMongoDBCertDepot(ctx, opt)
			require.NoError(t, err)
			return d
		},
		TearDown: func(t *testing.T) {
			require.NoError(t, client.Database(databaseName).Collection(depotName).Drop(ctx))
		},
		ServiceName: "test_service",
		CAName:      "test_ca",
	}

	testutil.RunBootstrapSuite(ctx, t, &impl)
}

func TestBootstrapDepotConfigValidate(t *testing.T) {
	for _, test := range []testutil.BootstrapConfigCase{
		{
			Name: "ValidMongoDepot",
			Conf: certdepot.BootstrapDepotConfig{
				CAName:      "root",
				ServiceName: "localhost",
				CACert:      "ca cert",
				CAKey:       "ca key",
			},
		},
		{
			Name: "Unconfigured",
			Conf: certdepot.BootstrapDepotConfig{
				ServiceName: "localhost",
			},
			Fail: true,
		},
		{
			Name: "MissingServiceName",
			Conf: certdepot.BootstrapDepotConfig{
				CAName: "root",
				CACert: "ca cert",
				CAKey:  "ca key",
			},
			Fail: true,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			if test.Fail {
				assert.Error(t, test.Conf.Validate())
			} else {
				assert.NoError(t, test.Conf.Validate())
			}
		})
	}
}
