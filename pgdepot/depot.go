package pgdepot

import (
	"context"
	"time"

	"github.com/deciduosity/certdepot"
	"github.com/jmoiron/sqlx"
	"github.com/square/certstrap/depot"
)

type pgDepot struct {
	db   *sqlx.DB
	opts Options
}

type Options struct {
	DepotOptions certdepot.Options
}

func NewDepot(ctx context.Context, db *sqlx.DB, opts Options) (certdepot.Depot, error) {
	return certdepot.MakeDepot(&pgDepot{db: db, opts: opts}, opts.DepotOptions), nil
}

func (pg *pgDepot) Put(tag *depot.Tag, data []byte) error                 { return nil }
func (pg *pgDepot) Get(tag *depot.Tag) ([]byte, error)                    { return nil, nil }
func (pg *pgDepot) Check(tag *depot.Tag) bool                             { return false }
func (pg *pgDepot) Delete(tag *depot.Tag) error                           { return nil }
func (pg *pgDepot) Save(name string, creds *certdepot.Credentials) error  { return nil }
func (pg *pgDepot) Find(name string) (*certdepot.Credentials, error)      { return nil, nil }
func (pg *pgDepot) Generate(name string) (*certdepot.Credentials, error)  { return nil, nil }
func (pg *pgDepot) PutTTL(name string, cutoff time.Time) error            { return nil }
func (pg *pgDepot) GetTTL(name string) (time.Time, error)                 { return time.Time{}, nil }
func (pg *pgDepot) FindExpiresBefore(time.Time) ([]certdepot.User, error) { return nil, nil }
func (pg *pgDepot) DeleteExpiresBefore(time.Time) error                   { return nil }
