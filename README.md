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

Gatekeeper routes between three (configurable) endpoints:
* `$PATH -> /public/$PATH` for anonymous requests.
* `$PATH -> /registered/$PATH` for authenticated but unauthorized requests.
* `$PATH -> /protected/$PATH` for authenticated and authorized requests.

Authorization is based on claims in the JWT token presented to the gatekeeper.
By default the gatekeeper matches emails in the token to a whitelist. It can
also be configured to match a list of required scopes.

## Running and Deploying

### Running from command-line

Either of the following:

```bash
mvn clean spring-boot:run
```

or

```bash
mvn clean package
java -jar target/*.jar
```

### Running with IntelliJ

After importing the project, find the `GatekeeperApp` class. Right-click it and run.

### Default Config

Gatekeeper is a 12-factor application. It logs to stdout, is configured by environment variables, and does not
treat the local filesystem as a safe place to persist its data.

This project is configured with a default implementation pointing to httpbin that
works with zero configuration.

The default configuration uses the RS256 JWT signing algorithm. To create or validate your
own tokens you can go to [jwt.io](https://jwt.io) and use these keys:

##### Private
```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxRvdt2Mrt1ZjX4KCSdFHNMEuENtrZzXv8Tkd0q572PGPHPx3
xnkj5qNA8BZzWsb1s+MTtyW7WGuQ0V9iipBjutA6X8wyGoNIEZtkWM2Xp61YMq3n
NetHoW4GR7S7ILirMVO0coBHrRnsKFKMKf3ZjL0s8xuy1EsTMmYBb3jdMqZxOpGg
yQB4t2rUfYbHkspDQqEK6qWxNkHsX8YbQucxqhu2ud2QWPczG3t11jdMWSF//yAp
yfOUn7X9fkhMxGMDQrvZ7W3BKOKZ6jYcm3vM40X5kGJHax0ZU2KeaVAl8qrJSE7c
Oiv6TxnIcBJ00isVdLggzz72xK5R9R1e9MEODQIDAQABAoIBAQCA/u2pOOPBRm4e
cYDm4mlhYxPMwGyXzTrMeX7FBJ/UqLHqXGfeoiUWqbyz4113CUJ/iZq7f5wOD8dk
3rHU0Q4TknbBfxdDNquRqkqPu20GtXFFKX5pUSM9yI2fm+3jSjfvPkKXtNAzvwVI
lk1YpeMcMioaqAPu33sevpct5sGMhS71S1t8oIJ82d4e7t53nWSWYs7AAbUf3zbb
mcXag6UiqMeuXk3m+eLC/s6gwyOm4FcS54SKKt9EcweaZwk89oBrQRdoeqzvejfZ
rrwC19LVNggr2DVsaAMV7VKV0C6xJoY1eitqgKKjZqsD5cQupAqou89hGRhYbqoU
Ad3jJ7zBAoGBAOYpWUxrHfcrDD8v6GgP/nW4co3KQpWHKiq5pPjVmFrj96HqHZiL
4adAzfSHFTSnL7vo3ZSRtFZVAcU/csXG2PvyR04L2+k6pbn/gSzLvQLWObG57VQt
vr+RQjArOaJOJ0ZXLn6MWz/26kzVtwjpXvxLk6TSGDKVcKeRuqe18H9VAoGBANs8
nGvDrQ4dykcVdWtHRsguX7A8820KZpx+mb4RC8CRgkpF1fqokY4FhilL4CjA8yzF
gt6mNP4MVCVyfu9J2GbsXLQHkPm8m03u/SYL0NpHodNXGuv6YOuTTikCljf/oy9/
qHjeXWqpThaPejU4n0DTDuyscGZ3RxroQB8biqPZAoGAEdZMhF6c0OX2KgN1eHMc
3lSwFAsDxADYpL0EawBqsUiPjW3OY18b2tFr5LJ/UzhNu7tdSMFN/47Q909mfqtd
b5EkM4k5vsZ7x4FkqmsTt9+QUxS8rtRovwHr5j3DVq/F3W6uPMJ14+wn1lKNv9QO
N3FH/PMHSwxH0cS6eXrhK40CgYAo74dRg+bzRNK5NSOIlXV8+VO6p5bYXGHOhMEW
QT6NhV3rmmCa/hC3kQZ8/YLseSKu0G5gPm6UpR6tI1TaP1Kd3TJuFx+V0ga5pY81
JG2p5EguGwyW1Vh1hDrK44XDDQOeYdrGPtb4jIZdJgsultT9mKsnvAb8yvbG6mjW
piDb+QKBgFSVXaxQQgUzlXGg5amGKNll2pSWmcIq2PqDmSPUCUQLj0zA0rpfRQzV
53pem4cn7JfsV4xvQRlTqrdvtGObdSyTmkogUB8Ymk0v1F8oacRJnwBTwD0SVEUG
WNZ6QCnkEy3l3CWBReVCu5pP1//yWOv8S8jO4jDSCDyu9WuPwzGh
-----END RSA PRIVATE KEY-----
```
##### Public
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxRvdt2Mrt1ZjX4KCSdFH
NMEuENtrZzXv8Tkd0q572PGPHPx3xnkj5qNA8BZzWsb1s+MTtyW7WGuQ0V9iipBj
utA6X8wyGoNIEZtkWM2Xp61YMq3nNetHoW4GR7S7ILirMVO0coBHrRnsKFKMKf3Z
jL0s8xuy1EsTMmYBb3jdMqZxOpGgyQB4t2rUfYbHkspDQqEK6qWxNkHsX8YbQucx
qhu2ud2QWPczG3t11jdMWSF//yApyfOUn7X9fkhMxGMDQrvZ7W3BKOKZ6jYcm3vM
40X5kGJHax0ZU2KeaVAl8qrJSE7cOiv6TxnIcBJ00isVdLggzz72xK5R9R1e9MEO
DQIDAQAB
-----END PUBLIC KEY-----
```

#### Sample Requests

Once you have the server running, here are some curl requests you can do
to test different access levels. The response payloads come from httpbin.

You will see that the different requests get proxied to different paths depending
on the token content.

You can copy the tokens and use [jwt.io](https://jwt.io) to see their contents.

##### Unauthenticated

```bash
curl --request GET \
  --url http://localhost:8082/beacon/foo
```

##### Authenticated but Unauthorized

```bash
curl --request GET \
  --url http://localhost:8082/beacon/foo \
  --header 'authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJnYXRla2VlcGVyIiwic3ViIjoidXNlciIsImF6cCI6ImNsaWVudCIsInNjb3BlIjpbIm9wZW5pZCJdLCJhY2NvdW50cyI6W3siaXNzdWVyIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwiZW1haWwiOiJ1bnJvYXN0ZWRAY29mZmVlLmJlYW4ifV0sImV4cCI6IjQxMDI0NDQ4MDAiLCJqdGkiOiJ0b2tlbi1pZCJ9.RiwN-YYQby9n0_eoyfCEf8QVsBA2ePF6yPWOw_cjbsG8oi_-oXbn_Z97fIIcgPec7XI-2R0uPHo2HJPFhp5Cb7lG3arS7lM2R4mZYOY3tPWmDVlGnvc_D1F9GMRcvnberGo7TQRDJAih30JneP3b9Zxw-j4Ra7wmoJ5gZoweSEw_Rvk202WmDEzude3-BAEtZHS9uxhlItuF2aLFhD9GmbGkamIevHjb5bYCsAsjiQ88HkiuTE3UYbIueWnIhciMWQNuQeDGFLyc7mCEcarRno_gHbdq8I7yHHbU5vpeHpbGrdfTTgzDmGl3Kco-LYDXwHx4m4O14SbIavsTKFf-xQ'
```

##### Authorized

```bash
curl --request GET \
  --url http://localhost:8082/beacon/foo \
  --header 'authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJnYXRla2VlcGVyIiwic3ViIjoidXNlciIsImF6cCI6ImNsaWVudCIsInNjb3BlIjpbIm9wZW5pZCJdLCJhY2NvdW50cyI6W3siaXNzdWVyIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwiZW1haWwiOiJyb2FzdGVkQGNvZmZlZS5iZWFuIn1dLCJleHAiOiI0MTAyNDQ0ODAwIiwianRpIjoidG9rZW4taWQifQ.G6ByK_Ktyr-yWUPmgy86MqLB_UzZjq9WPtjCw5ZO81FBMDj58f5Dd4Y_LOt52Wn4pG_V-08TbqI7VJfWOULXpEbdv_bBAEjkuHFFKU5EfKGGfPpkWtDf61eiw9jdm_D--ZOv6gvlcBfRf8JfGtUc_6Hn3XpKj43xiQOOjWvSZwHChI_yuqxJewzKXbF2fB89irQ9fOHCDPPecp4LICvcGoU6XDsaB9oUbd8kow4GxddfBUwA7vLnbkPLljg6NYU_osSjXnQC8FD80tdcWIYjVtNuomw1SIKSG3r2octchBh52dV47sTcemNVK8fFAyZ-EgoXi1W13NsMu15nn6lAEA'
```

### Configuration

For a non-default configuration (a deployment or a local-to-cloud integration scenario), these are the
environment variables that you may want to set:

* `INBOUND_JWT_0_ISSUER` - the issuer url associated with the public key signing inbound JWTs
* `INBOUND_JWT_0_PUBLIC_KEY` - the PEM-formatted public key of the Wallet server this Gatekeeper will trust
* `GATEKEEPER_BEACONSERVER_URL` - the URL of the beacon server being protected (proxied)
* see [application.yml](src/main/resources/application.yml) for more

