#!/bin/bash
#
# Copyright (c) 2021 Fraunhofer AISEC
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

# Open points:
# Handling of nonce
# How to transfer entities. Should we have import/export for
# issuer/nonce/parameters/credential requests/proof/users
# or should they be provided as a CLI argument?
# Idea: Have long living stuff/re-usable (issuer, user, parameters, signed
# credential) with import/export and short living stuff/one-use stuff
# (credential request, proof) as parameters

#########
# Step 0: Prepare setup
#########

# Create an issuer
./src/pabc-issuer --create-issuer TESTissuer

# Create a set of parameters
./src/pabc-issuer --issuer TESTissuer --create-parameter TESTparams --attributes Akey,Bkey,Ckey

# Export / Import of issuer
# Issuer needs to be public. Users and verifiers need to import it.
JSON_PP=$(./src/pabc-issuer --params TESTparams --export)

#########
# Step 1: A user can now create credential requests
#########

./src/pabc-user --import-params "${JSON_PP}" --params TESTparams

# Create a user
./src/pabc-user --params TESTparams --create-user TESTuser

# Set attributes
./src/pabc-user --params TESTparams --user TESTuser --set-attr "Akey=Aval"
./src/pabc-user --params TESTparams --user TESTuser --set-attr "Bkey=Bval"
#./src/pabc-user --params TESTparams --user TESTuser --set-attr "Ckey=Cval"

# Get a nonce/challenge to use for the CR.
JSON_NONCE=$(./src/pabc-issuer --get-nonce)
echo "JSON_NONCE: ${JSON_NONCE}"

# Generate CR
JSON_CR=$(./src/pabc-user --params TESTparams --user TESTuser --create-cr "${JSON_NONCE}")
echo "JSON_CR: ${JSON_CR}"

#########
# Step 2:
#########

# Issuer now checks CR.

# Issuer is ok with CR -> generate credential 
JSON_CERT=$(./src/pabc-issuer --issuer TESTissuer --params TESTparams --expected-nonce "${JSON_NONCE}" --sign "${JSON_CR}")
echo "JSON_CERT: ${JSON_CERT}"

#########
# Step 3:
#########

# User can now create blinded proofs

# Generate blinded proof
JSON_PROOF=$(./src/pabc-user --params TESTparams --user TESTuser --signed-cred "${JSON_CERT}" --reveal-attrs "Akey,Ckey")
echo "JSON_PROOF: ${JSON_PROOF}"

#########
# Step 4:
#########

./src/pabc-verifier --import-params "${JSON_PP}" --params TESTparams
# Verifier can now check the provided proof

# Verify proof
./src/pabc-verifier --params TESTparams --check "${JSON_PROOF}" && echo "SUCCESS :)"
