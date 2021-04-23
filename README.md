libpabc
=======

# Privacy-preserving Attribute-based Credentials
C implementation of [BBS+ blind signatures](https://github.com/ontio/ontology-crypto/wiki/Anonymous-Credential) using [BLS12-381](https://electriccoin.co/blog/new-snark-curve/).

A problem with the concept of [aggregated claims in combination with JWTs](https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims)
is excessive disclosure of information.
While anonymous credentials such as Camenisch-Lysyanskaya [1] using blind
signature schemes such as BBS+ can be used to enable selective disclosure of
attributes, such signature schemes are not explicitly defined for the OIDC
Aggregated Claims standard. For the [DISSENS project](https://wiki.geant.org/display/NGITrust/Funded+Projects+Call+2#FundedProjectsCall2-DISSENS),
we have implemented this library that supports non-interactive zero knowledge
proofs for the use case of self-sovereign identitiy.
In particular, we have implemented PABC credentials in
[re:claimID](https://reclaim-identity.io).

With PABC credentials, SSI systems can support users to effectively selectively
disclose attributes from a credential without invalidating the issuer’s
signature.

# How To Build

## Dependencies:

- doxygen
- libb64
- gmp
- jansson
- relic (pulled by cmake)

## Build library

```
$ mkdir build && cd build && cmake ../
$ make install (may need sudo)
```

# How to use

## Step 0: Prepare setup

### Create an issuer
```
pabc-issuer --create-issuer TESTissuer
```

### Create a set of parameters
```
pabc-issuer --issuer TESTissuer \
            --create-parameter TESTparams \
            --attributes Akey,Bkey,Ckey
```

### Export / Import of issuer. Issuer needs to be public. Users and verifiers need to import it.

```
JSON_PP=$(pabc-issuer --params TESTparams --export)
```

## Step 1: A user can now create credential requests

```
pabc-user --import-params "${JSON_PP}" --params TESTparams
```

### Create a user

```
pabc-user --params TESTparams --create-user TESTuser
```

### Set attributes

```
pabc-user --params TESTparams --user TESTuser --set-attr "Akey=Aval"
pabc-user --params TESTparams --user TESTuser --set-attr "Bkey=Bval"
```

### Get a nonce/challenge to use for the CR.
```
JSON_NONCE=$(pabc-issuer --get-nonce)
echo "JSON_NONCE: ${JSON_NONCE}"
```

### Generate a credential request

```
JSON_CR=$(pabc-user --params TESTparams --user TESTuser --create-cr "${JSON_NONCE}")
echo "JSON_CR: ${JSON_CR}"
```

## Step 2:

### Issuer now checks CR. If issuer is ok with CR -> generate credential

```
JSON_CERT=$(pabc-issuer --issuer TESTissuer \
                        --params TESTparams \
                        --expected-nonce "${JSON_NONCE}"\
                        --sign "${JSON_CR}")
echo "JSON_CERT: ${JSON_CERT}"
```

## Step 3:

### User can now create blinded proofs.

```
JSON_PROOF=$(pabc-user --params TESTparams \
                       --user TESTuser     \
                       --signed-cred "${JSON_CERT}" \
                       --reveal-attrs "Akey,Ckey")
echo "JSON_PROOF: ${JSON_PROOF}"
```

## Step 4:

```
pabc-verifier --import-params "${JSON_PP}" --params TESTparams
```

### Verify proof
```
pabc-verifier --params TESTparams --check "${JSON_PROOF}" && echo "SUCCESS :)"
```

# Structure

## `include/pabc/*.h`
This folder contains public API headers.

### `pabc.h`
Include this in your project to make use of libpabc.

### `pabc_json_creds.h`
This header provides a wrapper for raw pabc credentials that adds additional meta information. You probably want to make use of these functions in your project. All functions here are prefixed with `pabc_cred_`.

### `pabc_json_constants.h`
This header defines JSON key names used throughout libpabc.

## `src/*`
This folder contains the actual implementation. The files prefixed with `pabc-`
implement a proof-of-concept CLI.

## `tests/*` contains several test implementations

### Setup
See `setup_test` for general system setup and creation of issuer key pair.

### Credential Request
See `cred_request_test` for user key pair creation and credential request.

### Issue Credential
See `cred_issue_test` for issuing a credential.

### Proof / Presentation
See `proof_test` for creating a (blinded) proof/presentation.

### Verification
See `verify_test` for verification of a proof/presentation.

### `cli_example.sh`
This bash script demonstrates how to use the CLI. Run with
`../tests/cli_example.sh` from your `build` directory.

# Disclaimer
libpabc is meant to be a research sandbox in which we can (re)implement
protocols and potentially extend and modify functionality under the hood to
support research projects. It is NOT a production grade solution and should not
be used as such.

Implementations may not be correct or secure. Use at your own risk. This project
makes use of the RELIC toolkit for cryptography which considers itself "at most
alpha-quality software".

# Coding Style
Please use the provided `uncrustify.cfg`.


# References

1. J. Camenisch, M. Drijvers, and A. Lehmann. “Anonymous attestation using the strong diffie hellman assumption revisited”. In: International Conference on Trust and Trustworthy Computing. Springer. 2016, pp. 1–20.
2. Au, Man Ho, et al. "Constant-size dynamic k-times anonymous authentication." IEEE Systems Journal 7.2 (2012): 249-261.
