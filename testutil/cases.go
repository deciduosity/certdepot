package testutil

import (
	"context"
	"testing"

	"github.com/alecthomas/assert"
	"github.com/deciduosity/certdepot"
	"github.com/square/certstrap/depot"
	"github.com/stretchr/testify/require"
)

type DepotTest struct {
	Name string
	Test func(t *testing.T, d certdepot.Depot)
}

type DepotCase struct {
	Name    string
	Setup   func() certdepot.Depot
	Check   func(*testing.T, *depot.Tag, []byte)
	Cleanup func()
	Tests   []DepotTest
}

func (impl *DepotCase) Run(ctx context.Context, t *testing.T) {
	for _, test := range impl.Tests {
		t.Run(test.Name, func(t *testing.T) {
			d := impl.Setup()
			defer impl.Cleanup()

			test.Test(t, d)
		})
	}
	t.Run("Put", func(t *testing.T) {
		d := impl.Setup()
		defer impl.Cleanup()
		const name = "bob"

		t.Run("FailsWithNilData", func(t *testing.T) {
			assert.Error(t, d.Put(depot.CrtTag(name), nil))
		})
		t.Run("AddsDataCorrectly", func(t *testing.T) {
			certData := []byte("bob's fake certificate")
			assert.NoError(t, d.Put(depot.CrtTag(name), certData))
			impl.Check(t, depot.CrtTag(name), certData)
			impl.Check(t, depot.PrivKeyTag(name), nil)
			impl.Check(t, depot.CsrTag(name), nil)
			impl.Check(t, depot.CrlTag(name), nil)

			keyData := []byte("bob's fake private key")
			assert.NoError(t, d.Put(depot.PrivKeyTag(name), keyData))
			impl.Check(t, depot.CrtTag(name), certData)
			impl.Check(t, depot.PrivKeyTag(name), keyData)
			impl.Check(t, depot.CsrTag(name), nil)
			impl.Check(t, depot.CrlTag(name), nil)

			certReqData := []byte("bob's fake certificate request")
			assert.NoError(t, d.Put(depot.CsrTag(name), certReqData))
			impl.Check(t, depot.CrtTag(name), certData)
			impl.Check(t, depot.PrivKeyTag(name), keyData)
			impl.Check(t, depot.CsrTag(name), certReqData)
			impl.Check(t, depot.CrlTag(name), nil)

			certRevocListData := []byte("bob's fake certificate revocation list")
			assert.NoError(t, d.Put(depot.CrlTag(name), certRevocListData))
			impl.Check(t, depot.CrtTag(name), certData)
			impl.Check(t, depot.PrivKeyTag(name), keyData)
			impl.Check(t, depot.CsrTag(name), certReqData)
			impl.Check(t, depot.CrlTag(name), certRevocListData)
		})
	})
	t.Run("Check", func(t *testing.T) {
		d := impl.Setup()
		defer impl.Cleanup()
		const name = "alice"

		t.Run("ReturnsFalseWhenDNE", func(t *testing.T) {
			assert.False(t, d.Check(depot.CrtTag(name)))
			assert.False(t, d.Check(depot.PrivKeyTag(name)))
			assert.False(t, d.Check(depot.CsrTag(name)))
			assert.False(t, d.Check(depot.CrlTag(name)))
		})
		t.Run("ReturnsTrueForCorrectTag", func(t *testing.T) {
			data := []byte("alice's fake certificate")
			assert.NoError(t, d.Put(depot.CrtTag(name), data))
			assert.True(t, d.Check(depot.CrtTag(name)))
			assert.False(t, d.Check(depot.PrivKeyTag(name)))
			assert.False(t, d.Check(depot.CsrTag(name)))
			assert.False(t, d.Check(depot.CrlTag(name)))

			data = []byte("alice's fake private key")
			assert.NoError(t, d.Put(depot.PrivKeyTag(name), data))
			assert.True(t, d.Check(depot.CrtTag(name)))
			assert.True(t, d.Check(depot.PrivKeyTag(name)))
			assert.False(t, d.Check(depot.CsrTag(name)))
			assert.False(t, d.Check(depot.CrlTag(name)))

			data = []byte("alice's fake certificate request")
			assert.NoError(t, d.Put(depot.CsrTag(name), data))
			assert.True(t, d.Check(depot.CrtTag(name)))
			assert.True(t, d.Check(depot.PrivKeyTag(name)))
			assert.True(t, d.Check(depot.CsrTag(name)))
			assert.False(t, d.Check(depot.CrlTag(name)))

			data = []byte("alice's fake certificate revocation list")
			assert.NoError(t, d.Put(depot.CrlTag(name), data))
			assert.True(t, d.Check(depot.CrtTag(name)))
			assert.True(t, d.Check(depot.PrivKeyTag(name)))
			assert.True(t, d.Check(depot.CsrTag(name)))
			assert.True(t, d.Check(depot.CrlTag(name)))
		})
	})
	t.Run("Get", func(t *testing.T) {
		d := impl.Setup()
		defer impl.Cleanup()
		const name = "bob"

		t.Run("FailsWhenDNE", func(t *testing.T) {
			data, err := d.Get(depot.CrtTag(name))
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
		})
		t.Run("ReturnsCorrectData", func(t *testing.T) {
			certData := []byte("bob's fake certificate")
			assert.NoError(t, d.Put(depot.CrtTag(name), certData))
			data, err := d.Get(depot.CrtTag(name))
			assert.NoError(t, err)
			assert.Equal(t, certData, data)

			keyData := []byte("bob's fake private key")
			assert.NoError(t, d.Put(depot.PrivKeyTag(name), keyData))
			data, err = d.Get(depot.PrivKeyTag(name))
			assert.NoError(t, err)
			assert.Equal(t, keyData, data)

			certReqData := []byte("bob's fake certificate request")
			assert.NoError(t, d.Put(depot.CsrTag(name), certReqData))
			data, err = d.Get(depot.CsrTag(name))
			assert.NoError(t, err)
			assert.Equal(t, certReqData, data)

			certRevocListData := []byte("bob's fake certificate revocation list")
			assert.NoError(t, d.Put(depot.CrlTag(name), certRevocListData))
			data, err = d.Get(depot.CrlTag(name))
			assert.NoError(t, err)
			assert.Equal(t, certRevocListData, data)
		})
	})
	t.Run("Delete", func(t *testing.T) {
		d := impl.Setup()
		defer impl.Cleanup()
		const deleteName = "alice"
		const name = "bob"

		certData := []byte("alice's fake certificate")
		keyData := []byte("alice's fake private key")
		certReqData := []byte("alice's fake certificate request")
		certRevocListData := []byte("alice's fake certificate revocation list")
		require.NoError(t, d.Put(depot.CrtTag(deleteName), certData))
		require.NoError(t, d.Put(depot.PrivKeyTag(deleteName), keyData))
		require.NoError(t, d.Put(depot.CsrTag(deleteName), certReqData))
		require.NoError(t, d.Put(depot.CrlTag(deleteName), certRevocListData))

		data := []byte("bob's data")
		require.NoError(t, d.Put(depot.CrtTag(name), data))
		require.NoError(t, d.Put(depot.PrivKeyTag(name), data))
		require.NoError(t, d.Put(depot.CsrTag(name), data))
		require.NoError(t, d.Put(depot.CrlTag(name), data))

		t.Run("RemovesCorrectData", func(t *testing.T) {
			assert.NoError(t, d.Delete(depot.CrtTag(deleteName)))
			impl.Check(t, depot.CrtTag(deleteName), nil)
			impl.Check(t, depot.PrivKeyTag(deleteName), keyData)
			impl.Check(t, depot.CsrTag(deleteName), certReqData)
			impl.Check(t, depot.CrlTag(deleteName), certRevocListData)
			impl.Check(t, depot.CrtTag(name), data)
			impl.Check(t, depot.PrivKeyTag(name), data)
			impl.Check(t, depot.CsrTag(name), data)
			impl.Check(t, depot.CrlTag(name), data)

			assert.NoError(t, d.Delete(depot.PrivKeyTag(deleteName)))
			impl.Check(t, depot.CrtTag(deleteName), nil)
			impl.Check(t, depot.PrivKeyTag(deleteName), nil)
			impl.Check(t, depot.CsrTag(deleteName), certReqData)
			impl.Check(t, depot.CrlTag(deleteName), certRevocListData)
			impl.Check(t, depot.CrtTag(name), data)
			impl.Check(t, depot.PrivKeyTag(name), data)
			impl.Check(t, depot.CsrTag(name), data)
			impl.Check(t, depot.CrlTag(name), data)

			assert.NoError(t, d.Delete(depot.CsrTag(deleteName)))
			impl.Check(t, depot.CrtTag(deleteName), nil)
			impl.Check(t, depot.PrivKeyTag(deleteName), nil)
			impl.Check(t, depot.CsrTag(deleteName), nil)
			impl.Check(t, depot.CrlTag(deleteName), certRevocListData)
			impl.Check(t, depot.CrtTag(name), data)
			impl.Check(t, depot.PrivKeyTag(name), data)
			impl.Check(t, depot.CsrTag(name), data)
			impl.Check(t, depot.CrlTag(name), data)

			assert.NoError(t, d.Delete(depot.CrlTag(deleteName)))
			impl.Check(t, depot.CrtTag(deleteName), nil)
			impl.Check(t, depot.PrivKeyTag(deleteName), nil)
			impl.Check(t, depot.CsrTag(deleteName), nil)
			impl.Check(t, depot.CrlTag(deleteName), nil)
			impl.Check(t, depot.CrtTag(name), data)
			impl.Check(t, depot.PrivKeyTag(name), data)
			impl.Check(t, depot.CsrTag(name), data)
			impl.Check(t, depot.CrlTag(name), data)
		})
	})

}
