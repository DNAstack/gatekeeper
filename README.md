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
  --header 'authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJnYXRla2VlcGVyIiwic3ViIjoidXNlciIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MSIsImF6cCI6ImNsaWVudCIsInNjb3BlIjpbIm9wZW5pZCJdLCJleHAiOiI0MTAyNDQ0ODAwIiwianRpIjoidG9rZW4taWQifQ.vnlvQYKqRSQwoB-5woqi6jDojYZm1tI2Y7JTcn82Nh5iAsgaNSc52v6Zr0kI-OLBzTmJhZM76JxyH-t1SoPyS79BffEPiflYX7DxQVKACbnesChASv9P9CZNO0kxhdeBupiHbC_OM9NzdibHmeeGp_f_eS8yYRW0YZ2W0rTfsJYig0q4G2sFqHDAHZE3XhozVotsRhUiOcYI-oK5W1vYBpN9vzhFnFCOSM6B9QqKg3m-fdW89V_qH3EpK2lciu9DPvgo6ZA3jRlzUHLoxue-QdiTu11Vl7l4U3RcBylqgzhoSOsJqyVSpoAdfeJYr268ilpPUaDfRKX12sY8pgVj6Q'
```

##### Authorized

```bash
curl --request GET \
  --url http://localhost:8082/beacon/foo \
  --header 'authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJnYXRla2VlcGVyIiwic3ViIjoidXNlciIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MSIsImF6cCI6ImNsaWVudCIsInNjb3BlIjpbIm9wZW5pZCJdLCJnYTRnaCI6eyJDb250cm9sbGVkQWNjZXNzR3JhbnRzIjpbeyJ2YWx1ZSI6Imh0dHBzOi8vY29mZmVlLmJlYW4iLCJzb3VyY2UiOiJodHRwOi8vbG9jYWxob3N0OjgwODEiLCJieSI6ImRhYyJ9XX0sImV4cCI6IjQxMDI0NDQ4MDAiLCJqdGkiOiJ0b2tlbi1pZCJ9.iko_cYJuc7SVHmPTgqir2Zj16GAQz7SjJ2_c-Ygq7-OjtgAJNsyylH7Nz7A__qPVNKiH2i3vmLlJ-O51CLRiCESuQxfivE-KLJbqSt27ShZnvrsSDKrlIGbw-DT9Mnm1nOKdU1dFFJ9YkpXD_grQMN2EXjUjabnJCoJmp1VwCDzDHAaqhILWaF6iN5queV9hEDHLamR4oRDVNzI2fJadK5KGXI1vhMchha-bRzzXuxWgxzM2o1EbZbZ8LzR3lvRQNPLf-2LTRDrT8p-hNUZfw3gDmBelnWc7NotnBpMFdRYE8fSLmIWlYPzWpQWytaIIlbNXlspxV4A8X3Vjastz6w'
```

### Configuration

For a non-default configuration (a deployment or a local-to-cloud integration scenario), these are the
environment variables that you may want to set:

* `INBOUND_JWT_0_ISSUER` - the issuer url associated with the public key signing inbound JWTs
* `INBOUND_JWT_0_PUBLIC_KEY` - the PEM-formatted public key of the Wallet server this Gatekeeper will trust
* `GATEKEEPER_BEACONSERVER_URL` - the URL of the beacon server being protected (proxied)
* see [application.yml](src/main/resources/application.yml) for more

