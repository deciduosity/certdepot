======================================
``certdepot`` -- SSL Certificate Store
======================================

Overview
--------

Startup provides a set of tool Tools for creating and storing SSL certificates.

Certdepot is a higher level interface that wraps `certstrap
<https://github.com/square/certstrap>`_ by Square, and provides additional
ways of storing certificates and managing certificate workflows.

Certdepot is available under the terms of the Apache License (v2.)

Documentation
-------------

See the
`certdepot godoc <https://godoc.org/github.com/deciduosity/certdepot>`_ for
complete documentation of certdepot.

See the `certstrap godoc <https://godoc.org/github.com/square/certstrap>`_ for
complete documentation of certstrap.

Development
-----------

Testing
~~~~~~~

The certdepot project uses a ``makefile`` to coordinate testing. 

The makefile provides the following targets:

``build``
   Compiles non-test code.

``test``
   Runs all tests, sequentially, for all packages.

``test-<package>``
   Runs all tests for a specific package.

``race``, ``race-<package>``
   As with their ``test`` counterpart, these targets run tests with
   the race detector enabled.

``lint``, ``lint-<package>``
   Installs and runs the ``gometaliter`` with appropriate settings to
   lint the project.

The tests depend on having a running version of MongoDB.

Future Work
~~~~~~~~~~~

- Add additional backends, with support for additional databases including an
  embedded, and a SQL-based approach.

- Integration to support auto-rotation and renewal. 

Please file issues if there are other features you're interested in.'

Features
--------

Certificate Creation and Signing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SSL certificates and certificate authorities (CAs) can easily be created and
signed using Certdepot.

MongoDB Backed Depot
~~~~~~~~~~~~~~~~~~~~

Certdepot implements a certstrap
`depot <https://godoc.org/github.com/square/certstrap/depot#Depot>`_ backed by
MongoDB. This facilitates the storing and fetching of SSL certificates to and
from a Mongo database. There are various functions for maintaining the depot,
such as checking for expiration and rotating certs.

Bootstrap
~~~~~~~~~

Bootsrapping a depot facilitates creating a certificate depot with both a CA
and service certificate. ``BootstrapDepot`` currently supports bootstrapping
``FileDepots`` and ``MongoDepots``.

Examples
--------

Create a depot, initialize a CA in the depot, and create and sign service cert
with that CA in the depot: ::

	mongoOpts := certdepot.MongoDBOptions{} // populate options
	d, err := certdepot.NewMongoDBCertDepot(ctx, mongoOpts)
	// handle err

	certOpts := certdepot.CertificateOptions{
		Organization:       "mongodb",
		Country:            "USA",
		Locality:           "NYC",
		OrganizationalUnit: "evergreen",
		Province:           "Manhattan",
		Expires:            24 * time.Hour,

		IP:           []string{"0.0.0.0"},
		Domain:       []string{"evergreen"},
		URI:          []string{"evergreen.mongodb.com"},
		Host:         "evergreen",
		CA:           "ca",
		CAPassphrase: "passphrase",
		Intermediate: true,
	}

	// initialize CA named `ca` and stores it in the depot
	certOpts.Init(d)
	// creates a new certificate named `evergreen`, signs it with `ca`, and
	// stores it in the depot
	certOpts.CreateCertificate(d)

The following does the same as above, but now using the bootstrap
functionality: ::

	bootstrapConf := certdepot.BootstrapDepotConfig{
                MongoDepot:  mongoOpts,
		CAOpts:      certOpts,
		ServiceOpts: certOpts,
	}
	d, err := BootstrapDepot(ctx, bootstrapConf)
