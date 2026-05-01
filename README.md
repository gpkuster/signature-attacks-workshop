# Signature-Related Attacks Workshop

This workshop shows a common signature-verification bug in Solidity and a more realistic way to harden the authorization flow.

## What This Repo Demonstrates

The vulnerable contract uses `ecrecover` without validating the recovered signer. When `ecrecover` receives invalid parameters, it returns `address(0)` instead of reverting.

That creates a dangerous pattern:

```solidity
address signer = ecrecover(hash, v, r, s);
// missing validation
authorizedUsers[user] = true;
```

If the contract never checks the result, an attacker can submit malformed signature data and still pass the authorization path.

## Workshop Structure

### Vulnerable Contract
- `src/SignatureAttacks.sol`
- Demonstrates the `address(0)` / unchecked `ecrecover` issue

### Hardened Contract
- `src/SecureSignatureContract.sol`
- Rejects invalid signatures
- Requires a specific authorized signer
- Binds the signed payload to:
  - `address(this)`
  - `block.chainid`
  - `user`
  - `nonce`
  - `deadline`
- Prevents replay with `usedHashes`
- Includes an alternative packed-signature flow in `authorizeUserWithECDSA(...)`

### Tests
- `test/SignatureAttacks.t.sol`
- `test/SecureSignatureAttacks.t.sol`

The secure tests now cover:
- invalid signatures
- malformed signatures
- unauthorized signers
- expired signatures
- replay attempts
- packed-signature validation paths
- signature malleability checks

## Security Lessons

### 1. Checking `signer != address(0)` Is Necessary but Not Sufficient

That protects against one specific failure mode of `ecrecover`, but a secure authorization system also needs to answer:

- Who is allowed to sign?
- What exactly was signed?
- Can the signature be replayed?
- Can it expire?
- Is the signature malleable?

### 2. Bind Signatures to Context

The hardened contract computes the authorization hash from:

```solidity
keccak256(abi.encode(address(this), block.chainid, user, nonce, deadline))
```

This reduces cross-contract and cross-chain replay risk and ties the signature to a specific authorization action.

### 3. Validate the Signer, Not Just the Signature Shape

A valid signature from the wrong private key should still be rejected.

### 4. Add Replay and Expiry Protection

The secure contract tracks used hashes and rejects signatures after `deadline`.

## Running the Workshop

### Prerequisites

- Foundry installed
- Basic Solidity knowledge

### Install dependencies

If `forge-std` is missing, install it from the repo root:

```bash
forge install foundry-rs/forge-std --no-commit
```

### Run tests

```bash
forge test
```

Or run each suite independently:

```bash
forge test --match-contract SignatureAttacksTest
forge test --match-contract SecureSignatureAttacksTest
```

### Coverage

```bash
forge coverage
```

Note: some nightly Foundry builds on macOS may panic during `forge test` / `forge coverage` due to an internal tooling bug unrelated to this repo. If that happens, switch to a stable Foundry release and rerun.

## Expected Outcomes

### Vulnerable Contract

These tests should pass because the contract is intentionally insecure:

```text
testVulnerabilityWithInvalidSignature
testVulnerabilityWithMalformedSignature
```

### Hardened Contract

These tests should pass because the contract rejects unsafe flows:

```text
testRejectsInvalidSignature
testRejectsUnauthorizedSigner
testRejectsExpiredSignature
testAuthorizeUserWithECDSARejectsReplay
testAuthorizeUserWithECDSARejectsMalleableS
```

## Key Takeaways

1. Never trust raw `ecrecover` output without validation.
2. Reject `address(0)` recoveries.
3. Verify that the recovered signer is an authorized signer.
4. Include contract, chain, nonce and expiry in the signed message.
5. Protect against replay and signature malleability.
6. Test both the happy path and the failure paths.
