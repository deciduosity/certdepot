package pgdepot

import (
	"context"
	"fmt"
	"testing"

	"github.com/deciduosity/certdepot"
	"github.com/deciduosity/certdepot/testutil"
	"github.com/deciduosity/grip"
	"github.com/deciduosity/grip/message"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/square/certstrap/depot"
	"github.com/stretchr/testify/require"
)

func GetTestDatabase(bctx context.Context, t *testing.T) (*sqlx.DB, func() error) {
	db, closer, err := MakeTestDatabase(bctx, uuid.New().String()[0:7])
	require.NoError(t, err)

	return db, closer
}

func MakeTestDatabase(bctx context.Context, name string) (*sqlx.DB, func() error, error) {
	ctx, cancel := context.WithCancel(bctx)
	dbName := "certdepot_testing_" + name

	tdb, err := sqlx.ConnectContext(ctx, "postgres", "user=certdepot database=postgres sslmode=disable")
	if err != nil {
		return nil, nil, err
	}
	tdb.SetMaxOpenConns(128)
	tdb.SetMaxIdleConns(8)

	_, _ = tdb.Exec("CREATE DATABASE " + dbName)

	db, err := sqlx.ConnectContext(ctx, "postgres", fmt.Sprintf("user=certdepot database=%s sslmode=disable", dbName))
	if err != nil {
		return nil, nil, err
	}

	db.SetMaxOpenConns(128)
	db.SetMaxIdleConns(8)

	closer := func() error {
		cancel()
		catcher := grip.NewBasicCatcher()
		catcher.Wrap(db.Close(), "problem closing test database")

		_, err = tdb.Exec("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1;", dbName)
		catcher.Wrap(err, "problem killing connections")

		_, err = tdb.Exec("DROP DATABASE " + dbName)
		if perr, ok := err.(*pq.Error); ok && perr.Code == "3D000" {
			grip.Debug(errors.Wrap(err, "error dropping database"))
		} else {
			catcher.Wrap(err, "error dropping database")
		}

		catcher.Wrap(tdb.Close(), "problem closing connection")
		grip.Critical(message.WrapError(catcher.Resolve(), "problem cleaning up test database"))
		return nil
	}

	return db, closer, nil
}

func TestBootstrap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		db     *sqlx.DB
		closer func() error
	)

	impl := testutil.BootstrapSuite{
		Name: "PostgresDepot",
		Setup: func(t *testing.T, conf *certdepot.BootstrapDepotConfig) certdepot.Depot {
			db, closer = GetTestDatabase(ctx, t)

			d, err := NewDepot(ctx, db, Options{})
			require.NoError(t, err)
			return d
		},
		TearDown: func(t *testing.T) {
			require.NoError(t, closer())
		},
		ServiceName: "test_service",
		CAName:      "test_ca",
	}

	testutil.RunBootstrapSuite(ctx, t, &impl)
}

func TestDepot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		db     *sqlx.DB
		closer func() error
	)

	impl := testutil.DepotCase{
		Name: "MongoDB",
		Setup: func() certdepot.Depot {
			db, closer = GetTestDatabase(ctx, t)

			d, err := NewDepot(ctx, db, Options{})
			require.NoError(t, err)
			return d
		},
		Check: func(t *testing.T, tag *depot.Tag, data []byte) {
			// TODO add more checks (?)
			require.NotNil(t, tag)
			require.NotNil(t, data)
		},
		Cleanup: func() {
			require.NoError(t, closer())
		},
		// TODO add more cases (?)
		Tests: []testutil.DepotTest{},
	}

	t.Run(impl.Name, func(t *testing.T) { impl.Run(ctx, t) })
}

// TODO add test cases to cover TTL cases.
