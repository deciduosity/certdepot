package mdepot

import (
	"context"
	"testing"
	"time"

	"github.com/deciduosity/certdepot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestDB(t *testing.T) {
	const (
		uri            = "mongodb://localhost:27017"
		databaseName   = "certDepot"
		collectionName = "certs"
		dbTimeout      = 5 * time.Second
	)
	for name, testCase := range map[string]func(ctx context.Context, t *testing.T, md certdepot.ExpirationManager, client *mongo.Client, coll *mongo.Collection){
		"PutTTL": func(ctx context.Context, t *testing.T, md certdepot.ExpirationManager, client *mongo.Client, coll *mongo.Collection) {
			caName := "ca"
			serviceName := "localhost"

			for subTestName, subTestCase := range map[string]func(ctx context.Context, t *testing.T, md certdepot.ExpirationManager){
				"SetsValueOnExistingDocument": func(ctx context.Context, t *testing.T, md certdepot.ExpirationManager) {
					name := "foo"
					opts := &certdepot.CertificateOptions{
						CA:         caName,
						CommonName: name,
						Host:       name,
						Expires:    24 * time.Hour,
					}
					require.NoError(t, opts.CreateCertificate(md))

					dbUser := &certdepot.User{}
					require.NoError(t, coll.FindOne(ctx, bson.M{userIDKey: name}).Decode(dbUser))

					assert.WithinDuration(t, time.Now().Add(opts.Expires), dbUser.TTL, time.Minute)
				},
				"DoesNotInsert": func(ctx context.Context, t *testing.T, md certdepot.ExpirationManager) {
					name := "user"
					ttl := time.Now()
					require.Error(t, md.PutTTL(name, ttl))
					dbUser := &certdepot.User{}
					assert.Equal(t, mongo.ErrNoDocuments, coll.FindOne(ctx, bson.M{userIDKey: name}).Decode(dbUser))
				},
			} {
				t.Run(subTestName, func(t *testing.T) {
					tctx, cancel := context.WithTimeout(ctx, dbTimeout)
					defer cancel()

					conf := certdepot.BootstrapDepotConfig{
						CAName:      caName,
						ServiceName: serviceName,
						CAOpts: &certdepot.CertificateOptions{
							CommonName: caName,
							Expires:    24 * time.Hour,
						},
						ServiceOpts: &certdepot.CertificateOptions{
							CA:         caName,
							CommonName: serviceName,
							Host:       serviceName,
							Expires:    24 * time.Hour,
						},
					}

					dpt, err := NewMongoDBCertDepot(
						tctx,
						&MongoDBOptions{
							MongoDBURI:     uri,
							DatabaseName:   databaseName,
							CollectionName: collectionName,
						},
					)

					d, err := certdepot.BootstrapDepot(ctx, dpt, conf)
					require.NoError(t, err)
					defer func() {
						assert.NoError(t, client.Database(databaseName).Drop(ctx))
					}()

					md, ok := d.(certdepot.ExpirationManager)
					require.True(t, ok)
					subTestCase(tctx, t, md)
				})
			}
		},
		"GetTTL": func(ctx context.Context, t *testing.T, md certdepot.ExpirationManager, client *mongo.Client, coll *mongo.Collection) {
			for subTestName, subTestCase := range map[string]func(ctx context.Context, t *testing.T){
				"FailsForNonexistentDocument": func(ctx context.Context, t *testing.T) {
					_, err := md.GetTTL("nonexistent")
					assert.Error(t, err)
				},
				"PassesForExistingDocument": func(ctx context.Context, t *testing.T) {
					name := "user"
					expiration := time.Now()
					user := &certdepot.User{
						ID:            name,
						Cert:          "cert",
						PrivateKey:    "key",
						CertReq:       "certReq",
						CertRevocList: "certRevocList",
						TTL:           expiration,
					}
					_, err := coll.InsertOne(ctx, user)
					require.NoError(t, err)

					dbExpiration, err := md.GetTTL(name)
					require.NoError(t, err)

					assert.WithinDuration(t, expiration, dbExpiration, time.Second)
				},
			} {
				t.Run(subTestName, func(t *testing.T) {
					require.NoError(t, coll.Drop(ctx))
					defer func() {
						assert.NoError(t, coll.Drop(ctx))
					}()
					tctx, cancel := context.WithTimeout(ctx, dbTimeout)
					defer cancel()
					subTestCase(tctx, t)
				})
			}
		},
		"FindExpiresBefore": func(ctx context.Context, t *testing.T, md certdepot.ExpirationManager, client *mongo.Client, coll *mongo.Collection) {
			for subTestName, subTestCase := range map[string]func(ctx context.Context, t *testing.T){
				"MatchesExpired": func(ctx context.Context, t *testing.T) {
					name1 := "user1"
					name2 := "user2"
					ttl := time.Now()
					expiration := ttl.Add(time.Hour)
					userBeforeExpiration := &certdepot.User{
						ID:  name1,
						TTL: ttl,
					}
					userAfterExpiration := &certdepot.User{
						ID:  name2,
						TTL: expiration.Add(time.Hour),
					}

					_, err := coll.InsertOne(ctx, userBeforeExpiration)
					require.NoError(t, err)
					_, err = coll.InsertOne(ctx, userAfterExpiration)
					require.NoError(t, err)
					dbUsers, err := md.FindExpiresBefore(expiration)
					require.NoError(t, err)
					require.Len(t, dbUsers, 1)
					assert.Equal(t, userBeforeExpiration.ID, dbUsers[0].ID)
				},
				"IgnoresDocumentsWithoutTTL": func(ctx context.Context, t *testing.T) {
					name := "user"
					user := &certdepot.User{
						ID:            name,
						Cert:          "cert",
						PrivateKey:    "key",
						CertReq:       "certReq",
						CertRevocList: "certRevocList",
					}
					_, err := coll.InsertOne(ctx, user)
					require.NoError(t, err)
					dbUsers, err := md.FindExpiresBefore(time.Now())
					require.NoError(t, err)
					assert.Empty(t, dbUsers)
				},
			} {
				t.Run(subTestName, func(t *testing.T) {
					require.NoError(t, coll.Drop(ctx))
					defer func() {
						assert.NoError(t, coll.Drop(ctx))
					}()
					tctx, cancel := context.WithTimeout(ctx, dbTimeout)
					defer cancel()
					subTestCase(tctx, t)
				})
			}
		},
		"DeleteExpiresBefore": func(ctx context.Context, t *testing.T, md certdepot.ExpirationManager, client *mongo.Client, coll *mongo.Collection) {
			for subTestName, subTestCase := range map[string]func(ctx context.Context, t *testing.T){
				"MatchesExpired": func(ctx context.Context, t *testing.T) {
					name1 := "user1"
					name2 := "user2"
					ttl := time.Now()
					expiration := ttl.Add(time.Hour)
					userBeforeExpiration := &certdepot.User{
						ID:  name1,
						TTL: ttl,
					}
					userAfterExpiration := &certdepot.User{
						ID:  name2,
						TTL: expiration.Add(time.Hour),
					}

					_, err := coll.InsertOne(ctx, userBeforeExpiration)
					require.NoError(t, err)
					_, err = coll.InsertOne(ctx, userAfterExpiration)
					require.NoError(t, err)
					require.NoError(t, md.DeleteExpiresBefore(expiration))
					dbUsers := []certdepot.User{}
					res, err := coll.Find(ctx, bson.M{})
					require.NoError(t, err)
					require.NoError(t, res.All(ctx, &dbUsers))
					require.Len(t, dbUsers, 1)
					assert.Equal(t, userAfterExpiration.ID, dbUsers[0].ID)
				},
				"IgnoresDocumentsWithoutTTL": func(ctx context.Context, t *testing.T) {
					name := "user"
					user := &certdepot.User{
						ID:            name,
						Cert:          "cert",
						PrivateKey:    "key",
						CertReq:       "certReq",
						CertRevocList: "certRevocList",
					}
					_, err := coll.InsertOne(ctx, user)
					require.NoError(t, err)
					require.NoError(t, md.DeleteExpiresBefore(time.Now()))
					count, err := coll.CountDocuments(ctx, bson.M{})
					require.NoError(t, err)
					assert.EqualValues(t, 1, count)
				},
			} {
				t.Run(subTestName, func(t *testing.T) {
					require.NoError(t, coll.Drop(ctx))
					defer func() {
						assert.NoError(t, coll.Drop(ctx))
					}()
					tctx, cancel := context.WithTimeout(ctx, dbTimeout)
					defer cancel()
					subTestCase(tctx, t)
				})
			}
		},
	} {

		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
			require.NoError(t, err)

			opts := &MongoDBOptions{
				MongoDBURI:     uri,
				DatabaseName:   databaseName,
				CollectionName: collectionName,
			}

			d, err := NewMongoDBCertDepotWithClient(ctx, client, opts)
			require.NoError(t, err)

			mdbepot, ok := d.(certdepot.ExpirationManager)
			require.True(t, ok, "%T", d)

			testCase(ctx, t, mdbepot, client, client.Database(databaseName).Collection(collectionName))
		})
	}
}
