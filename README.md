# DNAstack Gatekeeper

NOTE: this project is deprecated. We are working on a similar product that we hope to release sometime in 2019. Until then,
this project is a reference implementation for our current federated auth model.

## What is it?

Gatekeeper is an HTTP reverse proxy that accepts JWT tokens that were created and signed by
[Wallet](https://github.com/DNAstack/plenary-wallet), verifies the claims in those tokens against a configured access
policy, and then returns an error or routes the original request to a protected backend endpoint. Every request and
response is logged along with the access decision that was made.

Thus, Gatekeeper solves the following cross-cutting concerns:

- authentication
- authorization
- audit logging

## Running and Deploying

Gatekeeper is a 12-factor application. It logs to stdout, is configured by environment variables, and does not
treat the local filesystem as a safe place to persist its data.

Wallet's default configuration should run locally and interoperate properly with a local Wallet server.

For a non-default configuration (a deployment or a local-to-cloud integration scenario), these are the
environment variables that you may want to set:

* `INBOUND_JWT_PUBLIC_KEY` - the PEM-formatted public key of the Wallet server this Gatekeeper will trust
* `GATEKEEPER_BEACONSERVER_URL` - the URL of the beacon server being protected (proxied)
* see [application.yml](src/main/resources/application.yml) for more
