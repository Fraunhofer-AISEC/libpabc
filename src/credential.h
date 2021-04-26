/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

// using the relic library https://github.com/relic-toolkit/

#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include "attributes.h"
#include "pabc/pabc_context.h"
#include "pabc/pabc_credential.h"
#include "pabc/pabc_utils.h"
#include <relic.h>

struct pabc_nonce;

struct pabc_credential
{
  //    A               G1Point
  g1_t A;
  //    B               G1Point
  g1_t B;
  //    e               BigNum
  bn_t e;
  //    s               BigNum
  bn_t s;

  g1_t Nym; // TODO can this be "public"?

  struct pabc_plain_attributes *plain_attrs;

  size_t nr_of_attributes;
};

struct pabc_credential_request
{
  // Nym             G1Point  //commitment to user's master secret
  g1_t Nym;
  // issuer nonce
  struct pabc_nonce *nonce;
  // //PoK that Nym is constructed as in the issuance protocol
  // // i.e. PoK{(sk): HSk^sk = Nym }
  // C               BigNum   //challenge in Sigma-protocol
  bn_t C;
  // S               BigNum   //response in Sigma-protocol
  bn_t S;

  struct pabc_plain_attributes *plain_attrs;
};

struct pabc_issuer_public_key
{
  // HAttrs         []G1Point // one G1-element for one attribute
  g1_t *HAttrs;
  // HRand          G1Point   // a random G1 point
  g1_t HRand;
  // HSk            G1Point   // a random G1 point to encode user's secret key
  g1_t HSk;

  // w              G2Point   // element from G2
  g2_t w;
  // _g1            G1Point   // point of G1
  g1_t _g1;
  // _g2            G1Point   // point of G1
  g1_t _g2;

  // PoK{x: w = g2^x && _g2 = _g1^x}
  // C              BigNum    // challenge
  bn_t C;
  // S              BigNum    // response
  bn_t S;
};

struct pabc_issuer_secret_key
{
  bn_t x;
};

struct pabc_blinded_proof
{
  // APrime             G1Point  // randomized pabc_credential signature values
  g1_t APrime;
  // ABar               G1Point  // randomized pabc_credential signature values
  g1_t ABar;
  // BPrime             G1Point  // randomized pabc_credential signature values
  g1_t BPrime;

  /* challenge in sigma-protocol */
  // ProofC             BigNum
  bn_t ProofC;
  /* response in sigma-protocol */
  // ProofSSk           BigNum
  bn_t ProofSSk;
  // ProofSE            BigNum
  bn_t ProofSE;
  // ProofSR2           BigNum
  bn_t ProofSR2;
  // ProofSR3           BigNum
  bn_t ProofSR3;
  // ProofSSPrime       BigNum
  bn_t ProofSSPrime;
  // ProofSAttrs        []BigNum
  bn_t *ProofSAttrs;

  // nonce used to avoid replay attack
  struct pabc_nonce *nonce;
  // Nym                G1Point
  g1_t Nym;

  struct pabc_attribute_predicates_D_I *DI;
};

struct pabc_public_parameters
{
  size_t nr_of_attributes;

  struct pabc_issuer_public_key *ipk;

  struct pabc_attributes *attrs;
};

#endif // CREDENTIAL_H
