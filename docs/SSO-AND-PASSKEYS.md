# Organization sign-in and passkeys

OpenWAF supports local passwords, local TOTP, WebAuthn passkeys and one optional OpenID Connect provider. Local roles and application assignments determine permissions for every method. Bootstrap recovery retains deployment-wide authority.

## Configure the console origin

Copy the packaged `authentication.conf.example` to a protected configuration file. Set `OPENWAF_AUTH_CONFIG` or `-auth-config` to its absolute path and restart the service. The strict JSON file has a 64-KiB limit. Omit `oidc` to use passkeys alone. Omit `passkey_rp_id` to use SSO alone. Authentication configuration stays separate from the traffic policy.

`origin` must exactly match the browser's scheme, hostname and port. HTTPS requires `OPENWAF_ADMIN_TLS_CERT` and `OPENWAF_ADMIN_TLS_KEY`, or the corresponding `-admin-tls-cert` and `-admin-tls-key` flags. The certificate must cover the origin hostname. Renewal uses the existing validated certificate watcher and records administration certificate activation. The administration listener remains loopback-only. Reach it through an authenticated tunnel and a locally resolved console hostname covered by its certificate. Forward the configured port unchanged.

For loopback development, `http://localhost:9443` with `passkey_rp_id` set to `localhost` is accepted. Open the browser on the tunnel client itself. HTTP on a remote hostname is rejected. A passkey RP ID must match the origin's DNS hostname. Keep both stable through upgrades and recovery. Keys registered under a previous RP ID cannot authenticate under a replacement RP ID. Plan a name migration with a working local TOTP administrator or the separately held bootstrap recovery credential. After changing the configured origin, enroll keys under the new name. Bootstrap key recovery may be needed for accounts whose only keys use the previous RP ID.

The optional OIDC client secret comes from the protected `client_secret_file` or `OPENWAF_OIDC_CLIENT_SECRET`. Configure one source. It must be readable by the service and at most 4096 bytes. A public client can omit the secret when its provider permits authorization code with PKCE. Private keys and client secrets belong in the deployment's secret-management and backup procedures.

## Organization identity

Register the exact callback `<origin>/auth/oidc/callback` at the provider. Configure its exact issuer and client ID. Discovery, authorization, token and signing-key endpoints require HTTPS, with an explicit loopback HTTP exception for local fixtures. The console uses authorization code with S256 PKCE, one-use state, browser cookie binding and nonce validation. Issuer, audience, signature, expiry and applicable token bindings are verified by the pinned Go OIDC implementation.

Create a local account first. In **Accounts & access**, bind the provider's immutable `sub` value to that account and provide a reason. Both issuer and subject participate in the mapping. Email addresses and provider role claims grant no access. Each subject belongs to one local account. Each account permits two bindings for a controlled identity transition. Unlinking a subject, disabling the account or changing its permissions invalidates existing account sessions and tokens.

When `required_acr` is configured, OpenWAF requests it and requires the exact returned `acr`, plus an `auth_time` within the preceding five minutes with a one-minute future clock allowance. Configure the provider to assign this value only after its required MFA policy succeeds. Confirm this behavior in the organization's provider before using SSO to satisfy administrator MFA. A missing or weaker assurance claim rejects sign-in. An account with local TOTP also requires assured SSO. Local administrator MFA enforcement gives weak authenticated administrator sessions enrollment-only access.

SSO sessions expire within 15 minutes and never outlive their verified ID token. Provider discovery and exchanges have five-second deadlines and a two-operation capacity limit. Provider access happens during sign-in. Service startup, traffic inspection, local passkeys and local password/TOTP authentication remain available during provider outages. OpenWAF does not implement provider-initiated logout or immediate remote revocation callbacks. Local unlink/disable revokes the account version immediately for subsequent requests.

## Passkeys

Use a browser supporting WebAuthn JSON conversion and a user-verifying authenticator. Sign in with a named local account, open **Passkeys**, supply the current password and an unused TOTP code when enrolled, then register a named key. An existing passkey account requires a recent strong sign-in before adding another key. A recent verified passkey or assured SSO session can authorize enrollment without entering a password again.

Registration requires user verification, exact configured origin and RP binding. Confirmation persists the public credential and revokes the previous account version. Sign in again with the account username and **Sign in with a passkey**. User verification is required on each assertion. OpenWAF stores up to four keys per account. Cryptographic verification uses the pinned Go WebAuthn verifier. The browser/authenticator retains the private key. Zero-counter authenticators remain supported according to the verifier's counter rules. A detected counter clone warning rejects sign-in, and a nonzero counter update is durably published before a session is issued.

Each registration/assertion ceremony is browser-bound, single-use, expires after two minutes and counts against a 100-ceremony limit. Local credential work shares the bounded verification slots and failure throttle. Passkey sessions satisfy administrator MFA. A password-only session for a passkey administrator receives enrollment-only access while deployment enforcement is enabled. When enforcement is disabled, password sign-in remains enabled. Configure enforcement to require a strong administrator session.

Own-key revocation requires a strong session verified within two minutes. Removing the last ready administrator's final local factor is refused during enforcement. Bootstrap recovery can reset an account's keys after a reason is recorded and keeps MFA enforcement active. Retain an independent recovery credential and a second enrolled administrator. A restored recovery set can restore credentials revoked after its checkpoint. Reconcile later changes before reopening administration.

## Durable state and deployment recovery

SSO bindings or passkey preparation select credential schema 4. Earlier credential schemas remain readable. Subsequent account, token and MFA edits preserve the selected format. Schema 4 permits 256 KiB for the combined credential document, with existing account/token bounds and four keys per account. Schemas 1–3 retain their 64-KiB limit. Management responses expose key metadata and count, with public-key blobs and opaque WebAuthn handles omitted.

Coordinated OpenWAF recovery sets preserve bindings, key public material, counters and enforcement. Preserve an earlier checkpoint and matching executable before selecting schema 4. Upgrade checks reject candidates that cannot read it. Policy rollback retains current credentials. Full recovery-set rollback restores checkpoint credentials intentionally.

Separately back up the protected authentication configuration, client secret, management certificate/key and tunnel/name configuration. These deployment files are outside the policy recovery set. Restore them with compatible permissions and the same browser origin. Provider client configuration and users remain under the organization's identity-provider recovery procedure.

The console reserves `openwaf_session`, `openwaf_oidc` and `openwaf_passkey`. These cookies are stripped before proxying to application backends, and backend attempts to set them are removed. Applications must choose different cookie names.

The implementation uses maintained verification libraries and established protocols. [Go OIDC](https://github.com/coreos/go-oidc), [Go WebAuthn](https://github.com/go-webauthn/webauthn), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [WebAuthn](https://www.w3.org/TR/webauthn-3/)
