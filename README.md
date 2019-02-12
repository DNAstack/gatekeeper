# DNAstack Gatekeeper

NOTE: this project is deprecated. We are working on a similar product that we hope to release sometime in 2019. This new product
will support dynamic updates of backends and access policies.
Until then, this project is a reference implementation for our current federated auth model.

## What is it?

Gatekeeper is an HTTP reverse proxy that accepts JWT tokens that were created and signed by
[Science ID](https://wallet.prod.dnastack.com/), verifies the claims in those tokens against a configured access
policy, and then returns an error or routes the original request to a protected backend endpoint. Every request and
response is logged along with the access decision that was made.

Thus, Gatekeeper solves the following cross-cutting concerns:

- authentication
- authorization
- audit logging

## Terminology

* *Resource Server*: the HTTP server for which Gatekeeper is a reverse proxy.

## Current Capabilities

At present Gatekeeper is able to use a statically configured whitelist for making authorization decisions about a
statically configured resource server. Gatekeeper uses http basic auth to authenticate itself with the resource server.

Gatekeeper routes between two hardcoded endpoints of the statically configured resource server URL: `$ROOT/public` and `$ROOT/private`.

When a request is made with a valid ID token and the email and issuer correspond to a whitelisted user, the `/public` endpoint is served.
Otherwise, the `/private` endpoint is served.

If no ID token is present in a reqest to Gatekeeper, the `/public` endpoint is returned with an additional `www-authenticate` header,
hinting to the requester that a login could return more information. (This is not a standard HTTP auth challenge as the response status may still be a 200.)

## Running and Deploying

Gatekeeper is a 12-factor application. It logs to stdout, is configured by environment variables, and does not
treat the local filesystem as a safe place to persist its data.

Wallet's default configuration should run locally and interoperate properly with a local Wallet server.

For a non-default configuration (a deployment or a local-to-cloud integration scenario), these are the
environment variables that you may want to set:

* `INBOUND_JWT_PUBLIC_KEY` - the PEM-formatted public key of the Wallet server this Gatekeeper will trust
* `GATEKEEPER_BEACONSERVER_URL` - the URL of the beacon server being protected (proxied)
* see [application.yml](src/main/resources/application.yml) for more

### To run Gatekeeper locally via IntelliJ

1. First, get a mysql instance up and running through docker. Run this command:

    `docker run --name mysql-gatekeeper -e MYSQL_ROOT_PASSWORD=abc123 -p 3306:3306 -d mysql-server:5.7`

2. Now you can run gatekeeper locally from inside IntelliJ.


