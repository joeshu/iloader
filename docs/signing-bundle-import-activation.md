# Signing Bundle import activation decision

## Decision

`iloader` will keep Signing Bundle import in **validated staging** mode for P1. A verified bundle is not automatically activated as a signing identity.

## Why activation is not enabled yet

The current `isideload` dependency (`feat/certificate-export`) exposes export APIs for the active signing identity and provisioning profiles, but it does not expose a supported API that can safely construct a signing session from an externally supplied PKCS#12 archive plus provisioning profiles.

`Sideloader::sign_app` always resolves the certificate identity through `CertificateIdentity::retrieve`. That path retrieves the account-scoped private key from `SideloadingStorage`, then searches Apple Developer certificates for a certificate matching both the stored key and the configured machine name. If it cannot find one, it requests a new development certificate. Therefore simply writing an imported private key into storage would not be a correct or safe implementation of bundle activation: it would couple imported key material to the active Apple account storage namespace, can fail the machine-name/certificate matching rules, and can unexpectedly cause certificate creation or revocation behavior.

The exported bundle also contains provisioning profiles, but the current `sign_app` path downloads fresh target provisioning profiles from Apple and does not accept externally supplied profile objects as an override. Injecting only the P12 would therefore not reproduce the exported signing session.

## P1 safety boundary

For P1, the import flow may:

- parse and validate the ZIP structure;
- verify SHA-256 checksums;
- validate Team ID and profile/application identifiers;
- parse the provisioning profiles;
- report that the bundle is structurally valid for the active team;
- keep the selected archive as a user-selected staging input for the current UI session.

It must not:

- persist `development.p12` automatically;
- persist the PKCS#12 password;
- overwrite the account-scoped private key in `SideloadingStorage`;
- silently replace or revoke Apple Developer certificates;
- claim that a validated bundle is an active signing identity.

## Required engine contract before activation can be added

A future `isideload` API should provide an explicit, session-scoped import contract, conceptually equivalent to:

1. parse PKCS#12 using a caller-supplied password;
2. verify certificate/private-key consistency;
3. verify certificate Team ID / serial / validity against the selected Developer Team;
4. accept the validated main and extension provisioning profiles explicitly;
5. verify every profile belongs to the same Team and signing Bundle ID set;
6. construct an in-memory signing identity and profile set without writing secrets to persistent storage;
7. sign using those supplied assets without invoking certificate creation/revocation or profile download;
8. zero/drop password and private-key buffers as soon as practical;
9. return an explicit result proving which certificate serial and profile UUIDs were used.

Only after such an API exists should iloader expose a password-gated **Activate / Sign with imported bundle** action.

## Current UI semantics

Until that engine contract exists, a successful import inspection means **Validated staging**, not **Activated**. No password prompt should be added solely for persistence into the existing account key store.
