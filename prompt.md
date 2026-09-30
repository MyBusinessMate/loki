# MASTER BUILD PROMPT: PRODUCTION-GRADE AGENCY PASSWORD MANAGER

You are a senior security engineer, cryptography-aware software architect, backend engineer, frontend engineer, DevSecOps engineer, QA engineer, and penetration tester working as one team.

Build a production-grade, self-hosted agency password manager for storing real client credentials.

This is a SECURITY-CRITICAL application.

Do not treat this as a normal CRUD dashboard.

The system must be designed so that compromise of the database, backups, API, or a single employee account does not automatically expose every stored secret.

Do not invent cryptographic primitives, authentication protocols, encryption schemes, or security mechanisms.

Use established, maintained, audited cryptographic libraries and standard protocols.

Do not use mock security.

Do not leave TODO security placeholders.

Do not say "can be implemented later."

Do not weaken requirements to make implementation easier.

Do not ask me unnecessary questions. Inspect the repository, infer the existing stack and architecture, preserve useful existing work, and make sensible production decisions. Only stop for a genuinely impossible or unsafe technical dependency.

If the repository is empty, choose a modern TypeScript stack with PostgreSQL. Prefer the existing project stack when present. If Supabase is already present, use Supabase/PostgreSQL and its supported authentication primitives rather than replacing the stack without reason.

Use current stable package versions available to the environment.

---

# 1. PRIMARY OBJECTIVE

---

Build a secure agency password manager with:

* Organizations
* Clients
* Users
* Roles
* Vaults
* Folders
* Credentials
* Secure notes
* API keys
* TOTP secrets
* Recovery codes
* SSH keys
* Environment secrets
* Attachments
* Password generator
* Search
* Sharing
* Temporary access
* Audit logs
* Security dashboard
* Employee onboarding
* Employee offboarding
* Client offboarding
* Ownership transfer
* Secure export
* Recovery
* Session/device management
* MFA
* Passkeys/WebAuthn where supported
* Automatic vault locking
* Clipboard protection
* Password health
* Key rotation
* Incident lockdown mode

The application must have a clean agency-focused UX but security takes priority over visual complexity.

---

# 2. NON-NEGOTIABLE SECURITY PRINCIPLE

---

The server must NOT receive plaintext vault secrets during normal vault operations.

The following must never be transmitted to the server as plaintext:

* Master password
* Vault passwords
* API secrets
* TOTP secrets
* Private SSH keys
* Recovery codes
* Secure notes
* Sensitive attachment contents
* Database passwords
* Environment secrets

Encryption/decryption of vault content must happen on the trusted client side.

The server may store:

* Authentication/account metadata
* Organization metadata
* Membership metadata
* Permission metadata
* Vault metadata
* Encrypted vault keys
* Encrypted item ciphertext
* Encrypted attachments
* Public keys
* Audit metadata
* Non-sensitive timestamps/IDs required for system operation

Do not claim that a browser application provides protection against a fully compromised deployment that serves modified JavaScript. Document this limitation clearly in the security architecture.

---

# 3. THREAT MODEL

---

Create THREAT-MODEL.md before or alongside implementation.

Explicitly model:

1. Database theft
2. Backup theft
3. API server compromise
4. Cloud storage compromise
5. Stolen employee credentials
6. Stolen session
7. Compromised employee device
8. Malicious employee
9. Privilege escalation
10. Cross-client access
11. Cross-organization access
12. IDOR/BOLA
13. XSS
14. CSRF
15. SQL injection
16. SSRF
17. Path traversal
18. Malicious file uploads
19. Credential stuffing
20. Brute-force attacks
21. Replay attacks
22. Token theft
23. Refresh-token abuse
24. Session fixation
25. Supply-chain compromise
26. Dependency compromise
27. Insider database access
28. Unauthorized exports
29. Audit-log tampering
30. Lost master password
31. Lost device
32. Employee offboarding
33. Emergency recovery
34. Key compromise
35. Encryption-key rotation
36. Malicious administrator

For every threat document:

* Attack
* Entry point
* Impact
* Preventive control
* Detection control
* Recovery procedure
* Relevant automated test

---

# 4. CRYPTOGRAPHIC ARCHITECTURE

---

Do not create custom cryptography.

Use an established cryptographic library such as a maintained libsodium binding or another audited equivalent available in the chosen stack.

Use:

* Argon2id for password-based key derivation
* XChaCha20-Poly1305 or AES-256-GCM for authenticated encryption
* CSPRNG provided by the OS/platform/library
* X25519 or another established public-key mechanism supported by the chosen cryptographic library
* HKDF where key derivation between cryptographic stages is required
* WebAuthn/passkeys through standards-compliant libraries/APIs

Choose ONE concrete cryptographic design and document it in CRYPTOGRAPHY.md.

Do not implement multiple competing crypto systems.

---

# 5. MASTER PASSWORD MODEL

---

The master password is NOT the vault encryption key.

Flow:

USER ENTERS MASTER PASSWORD
↓
Generate/use per-user KDF salt
↓
Argon2id
↓
Key Encryption Key (KEK)
↓
Decrypt encrypted private key and/or encrypted vault-key material
↓
Recover vault key
↓
Vault becomes unlocked locally

Rules:

* Never store the master password
* Never send the master password to the server
* Never log the master password
* Never place it in URL parameters
* Never place it in analytics
* Never store it plaintext in localStorage
* Never store it plaintext in sessionStorage
* Never include it in error reports
* Never expose it to third-party scripts

Document Argon2id parameters and the reasoning behind them.

Parameters must be configurable through a documented security configuration, not scattered through source code.

---

# 6. KEY HIERARCHY

---

Implement a proper key hierarchy.

Recommended model:

USER MASTER PASSWORD
↓
Argon2id
↓
User KEK
↓
Decrypt user's encrypted private key
↓
User private key
↓
Decrypt/wrap access to vault key
↓
Vault DEK
↓
Encrypt/decrypt vault items

Each vault gets its own random 256-bit vault encryption key.

Do NOT use one global encryption key for every customer/client/vault.

For shared vaults:

* Each authorized user has a public/private keypair
* Public key is stored server-side
* Private key is encrypted before being stored
* Private key can only be unlocked locally using the user's KEK
* Vault key is wrapped/encrypted to each authorized user's public key using established library functionality
* Server distributes encrypted key material
* Client unwraps/decrypts it locally

When removing a user:

* Remove their authorization
* Revoke their vault-key access metadata
* Revoke active sessions
* Revoke sharing permissions
* Record the action in the audit log

Document the limitation that revocation cannot erase plaintext that an already-authorized user may previously have copied or memorized.

---

# 7. VAULT ITEM ENCRYPTION

---

Sensitive item fields must be encrypted client-side.

At minimum encrypt:

* Username
* Password
* TOTP secret
* API keys
* Secure notes
* Recovery codes
* SSH private keys
* Environment values
* Database credentials
* Custom secret fields
* Sensitive attachments

Do not transmit plaintext sensitive values to the backend.

For each encryption operation:

* Generate a fresh unique nonce according to the selected primitive
* Use authenticated encryption
* Store algorithm/version metadata as needed
* Store ciphertext
* Store nonce
* Store key-version metadata
* Validate authentication tags automatically through the crypto library

Do not invent encryption serialization formats without necessity.

Preferred logical structure:

{
ciphertext,
nonce,
crypto_version,
key_version,
encrypted_metadata
}

Do not expose raw decrypted objects outside the secure vault layer.

---

# 8. ENCRYPTION FLOW

---

Implement and document this exact conceptual flow:

CREATE ITEM

User enters plaintext secret
↓
Client validates input
↓
Client obtains unlocked vault key from secure vault context
↓
Generate unique nonce
↓
AEAD encrypt
↓
Plaintext removed from normal UI state as soon as practical
↓
Ciphertext package sent over HTTPS
↓
Server validates authorization
↓
Server stores ciphertext
↓
Server never receives plaintext

READ ITEM

User requests item
↓
Server checks authentication
↓
Server checks organization membership
↓
Server checks vault permission
↓
Server returns encrypted item
↓
Client verifies/decrypts locally
↓
Plaintext shown only in secure UI state
↓
Reveal/copy action recorded as appropriate
↓
Clipboard cleared after configured duration
↓
Vault auto-lock removes key access

UPDATE ITEM

Retrieve encrypted item
↓
Client decrypts
↓
User modifies secret
↓
Client re-encrypts
↓
Fresh nonce
↓
Ciphertext sent to API
↓
Server stores ciphertext
↓
Create audit event

DELETE ITEM

Client requests delete
↓
Server authorizes
↓
Server deletes or tombstones encrypted object according to retention policy
↓
Audit event created
↓
Related encrypted attachments handled securely

---

# 9. AUTHENTICATION FLOW

---

Separate ACCOUNT AUTHENTICATION from VAULT UNLOCK.

ACCOUNT AUTH:

User
↓
Login/passkey/MFA
↓
Authentication provider/service
↓
Authenticated application session
↓
API access token/session

VAULT UNLOCK:

Authenticated user
↓
Enter master password
↓
Argon2id
↓
KEK
↓
Decrypt local/remote encrypted private-key material
↓
Decrypt/wrap vault-key material
↓
Vault unlocked only in client memory

The user can therefore be logged into the application without necessarily having the vault unlocked.

Implement:

* Email/password authentication through established auth infrastructure where appropriate
* MFA
* TOTP MFA
* WebAuthn/passkeys
* Recovery codes
* Login rate limiting
* Credential stuffing protection
* Suspicious-login detection
* Session expiry
* Idle timeout
* Absolute timeout
* Device/session listing
* Session revocation
* Refresh-token rotation
* Reauthentication for critical actions

Never build authentication cryptography from scratch.

---

# 10. AUTHENTICATION VS AUTHORIZATION

---

Authentication answers:

"Who is this user?"

Authorization answers:

"Can this user perform this action on this exact resource?"

Implement both independently.

Every server request that touches protected resources must verify:

* Identity
* Organization
* Membership
* Resource ownership/access
* Role
* Permission
* Action

Never trust:

* Frontend role
* User-submitted organization ID
* User-submitted client ID
* User-submitted vault ID
* User-submitted item ID

Treat every identifier as attacker-controlled.

---

# 11. ROLE AND PERMISSION MODEL

---

Implement organization roles such as:

* Owner
* Admin
* Manager
* Member
* Auditor
* Guest

But do not rely only on roles.

Support resource-level permissions.

Example:

USER
↓
ORGANIZATION
↓
CLIENT
↓
VAULT
↓
FOLDER
↓
ITEM
↓
ACTION

Actions:

* Read
* Reveal
* Copy
* Create
* Edit
* Share
* Export
* Delete
* Manage permissions

A user may have:

TecnoMart = Edit
Gold N Glow = View
Internal Finance = No access

Enforce this server-side.

---

# 12. MULTI-TENANT ISOLATION

---

The system must support organizations safely.

Logical structure:

Organization
├── Users
├── Clients
├── Vaults
├── Folders
├── Items
└── Audit logs

Organization A must never access:

Organization B's:

* clients
* vaults
* users
* items
* files
* keys
* audit logs

Implement database-level protections where supported, such as PostgreSQL RLS, alongside application-level authorization.

Test cross-tenant attacks explicitly.

---

# 13. CLIENT STRUCTURE

---

Support:

Organization
└── Client
└── Vault
└── Folder
└── Credential

Example:

Agency
├── TecnoMart
│    ├── Google
│    ├── Meta
│    ├── Website
│    └── Infrastructure
│
├── Gold N Glow
│    ├── Google
│    ├── Social
│    ├── Website
│    └── Marketing
│
└── Internal
├── Agency
├── Development
├── Infrastructure
└── Finance

---

# 14. ITEM TYPES

---

Support at minimum:

1. Login
2. API Key
3. Secure Note
4. TOTP
5. SSH Key
6. Database Credential
7. Environment Secret
8. Recovery Codes
9. Certificate
10. Custom Secret

Each item must support:

* Name
* Folder
* Client
* URL
* Username where relevant
* Password where relevant
* Secret fields
* Notes
* Tags
* Attachments
* Created timestamp
* Updated timestamp
* Last-access timestamp
* Expiration timestamp
* Ownership metadata
* Security state

Separate sensitive and non-sensitive fields intentionally.

---

# 15. SEARCH ARCHITECTURE

---

Do not create plaintext server-side indexes containing secrets.

Default architecture:

* Fetch authorized encrypted records
* Decrypt only what is required client-side
* Search locally
* Avoid unnecessarily persistent plaintext search indexes

Document the metadata leakage tradeoffs.

If exact-match blind indexes are implemented, use keyed constructions and document exactly what information they reveal.

---

# 16. TOTP

---

Implement TOTP securely.

Store the TOTP secret encrypted.

Display:

* Current code
* Countdown
* Issuer/account metadata where available

Treat TOTP secrets as equivalent to passwords.

Never log TOTP secrets.

---

# 17. PASSWORD GENERATOR

---

Implement cryptographically secure password generation.

Support:

* Length
* Uppercase
* Lowercase
* Numbers
* Symbols
* Excluded characters
* Passphrases

Use CSPRNG only.

Do not use Math.random().

---

# 18. ATTACHMENTS

---

Attachments must be encrypted client-side before upload.

Flow:

File selected
↓
Client validates size/type
↓
Encrypt file locally
↓
Upload ciphertext
↓
Private object storage
↓
Access controlled through API
↓
Signed URL only when appropriate
↓
Client downloads ciphertext
↓
Client decrypts locally

Implement:

* Size limits
* MIME validation
* Extension validation
* Safe filenames
* Malware scanning where appropriate
* Private object storage
* Signed URLs
* Expiring URLs
* Authorization checks
* Encrypted backups

Never put sensitive files in public buckets.

---

# 19. SHARING FLOW

---

Implement secure sharing.

Flow:

Owner chooses credential/vault
↓
Select authorized user
↓
Server verifies organization/membership
↓
Client obtains recipient public key
↓
Client wraps vault/item key for recipient
↓
Encrypted key material uploaded
↓
Recipient retrieves encrypted key material
↓
Recipient unlocks own private key locally
↓
Recipient decrypts wrapped key locally
↓
Recipient decrypts item locally

Support:

* View
* Reveal
* Copy
* Edit
* Share
* Export
* Delete

Support temporary sharing:

* Start time
* Expiry time
* Revocation

Record sharing activity.

---

# 20. EXPORT FLOW

---

Exports are high-risk.

Implement:

User requests export
↓
Check permission
↓
Require reauthentication
↓
Require MFA
↓
Optional admin approval for sensitive vaults
↓
Audit event
↓
Decrypt locally
↓
Generate export locally
↓
Prefer encrypted export format
↓
Never send decrypted export to server
↓
Secure download
↓
Auto-expire temporary export artifacts if any exist

Do NOT create a one-click plaintext CSV export accessible to normal members.

If plaintext export is supported, make it an explicitly protected high-risk operation.

---

# 21. RECOVERY

---

Design recovery deliberately.

A true zero-knowledge-style vault cannot simply recover a forgotten master password from the server.

Implement one of the following documented mechanisms:

* Recovery key
* Emergency access
* Organization recovery key
* Designated recovery administrators
* Combination of the above

Recovery material must itself be protected.

Document:

* What can be recovered
* Who can recover it
* What information the server can see
* What happens if all recovery material is lost
* How recovery is audited
* How recovery is revoked

Never create a fake "password reset = vault access" mechanism that bypasses the cryptographic model.

---

# 22. AUTO-LOCK

---

Implement vault auto-lock.

Configurable:

* 5 minutes
* 10 minutes
* 15 minutes
* 30 minutes
* custom policy
* immediately on browser/device lock where practical

When locking:

* Remove vault key references from application state
* Clear decrypted item cache
* Clear plaintext search cache
* Clear sensitive UI state
* Stop crypto workers where possible
* Clear clipboard where appropriate

Acknowledge that JavaScript memory zeroization is best-effort because garbage collection is controlled by the runtime.

Do not falsely claim guaranteed memory wiping.

---

# 23. CLIPBOARD

---

Support separate:

* Copy username
* Copy password
* Copy TOTP
* Copy API key

Implement automatic clipboard clearing after a configurable timeout.

Do not put sensitive values in persistent browser storage.

---

# 24. SESSION AND DEVICE MANAGEMENT

---

Build a session/device screen:

* Device name
* Browser
* OS
* Approximate location metadata if available
* Created time
* Last active
* Current session
* Revoke

Support:

* Revoke one session
* Revoke all sessions
* Admin global revoke where appropriate

Protect refresh tokens and session cookies correctly.

---

# 25. AUDIT LOGGING

---

Implement audit logs for:

* Login
* Failed login
* MFA change
* Passkey registration
* Passkey removal
* Session creation
* Session revocation
* User invitation
* User removal
* Role change
* Permission change
* Client creation
* Vault creation
* Item creation
* Item update
* Item deletion
* Credential reveal
* Credential copy
* Sharing
* Sharing revocation
* Export request
* Export completion
* Recovery
* Key rotation
* Employee offboarding
* Client offboarding
* Lockdown mode
* Admin activity

NEVER store secrets in audit logs.

Do not log:

* Passwords
* API keys
* TOTP secrets
* Private keys
* Recovery codes
* Master passwords
* Decrypted secure notes

Consider append-only/hash-chained audit records and, where practical, an independent immutable audit sink.

Clearly document the trust limitations of server-generated logs.

---

# 26. SECURITY DASHBOARD

---

Build a security dashboard showing:

* Weak credentials
* Reused credentials
* Old credentials
* Expiring credentials
* Missing MFA
* Suspicious sessions
* Recent sensitive activity
* Export activity
* Sharing activity
* Recently changed credentials
* Inactive users
* High-risk credentials
* Vault security status

Never expose the secret itself while reporting its security health.

---

# 27. PASSWORD HEALTH

---

Implement:

* Weak password detection
* Reused password detection
* Old password detection
* Expiry detection
* Missing MFA detection

Do this without unnecessarily exposing plaintext passwords to the server.

---

# 28. EMPLOYEE ONBOARDING

---

Implement:

Admin invites employee
↓
Employee creates/authenticates account
↓
MFA/passkey setup
↓
Client-side cryptographic identity/key generation
↓
Encrypted private key setup
↓
Assign clients/vaults
↓
Audit event

---

# 29. EMPLOYEE OFFBOARDING

---

Implement one controlled workflow:

OFFBOARD EMPLOYEE

Actions:

* Disable account
* Revoke sessions
* Revoke refresh tokens
* Remove organization membership
* Remove client access
* Remove vault permissions
* Revoke sharing permissions
* Transfer owned resources
* Preserve audit logs
* Mark offboarding complete

Require appropriate authorization.

---

# 30. CLIENT OFFBOARDING

---

Implement:

CLIENT CLOSED
↓
Freeze client access
↓
Remove active users
↓
Archive vaults
↓
Transfer ownership where required
↓
Export encrypted archive if requested
↓
Preserve audit history
↓
Apply retention policy

---

# 31. HIGH-RISK CREDENTIALS

---

Allow credentials to be marked:

* Normal
* Sensitive
* Critical

Critical examples:

* Production database
* Cloud root account
* DNS provider
* Payment processor
* Organization master administrator
* Infrastructure root credentials

For critical credentials optionally require:

* Reauthentication
* MFA
* Approval
* Enhanced audit logging
* Limited access
* Time-limited access

---

# 32. ORGANIZATION LOCKDOWN MODE

---

Implement:

LOCKDOWN MODE

When triggered:

* Revoke all active sessions
* Disable exports
* Disable new sharing
* Require reauthentication
* Freeze critical vault operations
* Alert authorized admins
* Create high-priority audit event

Allow controlled recovery after investigation.

---

# 33. KEY ROTATION

---

Support key versioning.

Example:

key_version = 1
key_version = 2
key_version = 3

Implement safe rotation without exposing plaintext secrets to the server.

When rotating a vault encryption key:

Old Vault Key
↓
Client decrypts existing items
↓
Generate new Vault Key
↓
Re-encrypt items with fresh nonces
↓
Wrap new Vault Key for authorized members
↓
Store new ciphertext/key material
↓
Retire old key metadata according to policy
↓
Audit event

Where full vault re-encryption is too expensive, provide a well-defined staged process rather than silently pretending rotation happened.

---

# 34. DATABASE DESIGN

---

Create a clear relational schema.

At minimum consider:

users
organizations
organization_memberships
clients
vaults
vault_members
folders
vault_items
item_versions
attachments
encrypted_key_wrappers
user_crypto_keys
sessions
devices
mfa_methods
recovery_methods
shares
audit_logs
security_events
invitations
approval_requests
lockdown_events

Use:

* UUIDs or cryptographically secure identifiers
* Foreign keys
* Unique constraints
* Check constraints
* Proper indexes
* Soft-delete only where justified
* Transaction boundaries
* Referential integrity

Never rely on frontend-generated authorization.

---

# 35. API DESIGN

---

Create clear APIs for:

Authentication
Users
Organizations
Clients
Vaults
Folders
Items
Attachments
Sharing
Permissions
Sessions
MFA
Passkeys
Recovery
Exports
Audit logs
Security dashboard
Lockdown
Key rotation

For every endpoint document:

* Input
* Authentication requirement
* Authorization requirement
* Validation
* Database operations
* Output
* Failure modes
* Audit event
* Rate-limit requirement

Return the minimum necessary information.

Never return unnecessary sensitive fields.

---

# 36. INPUT FLOW

---

For EVERY sensitive operation implement this pattern:

USER INPUT
↓
Frontend schema validation
↓
Normalize where appropriate
↓
Client-side authorization UX check
↓
Cryptographic transformation if sensitive
↓
HTTPS request
↓
Server authentication
↓
Server authorization
↓
Server validation again
↓
Database transaction
↓
Audit log
↓
Minimal response
↓
Client updates state

Never treat frontend validation as security.

---

# 37. ERROR FLOW

---

Never return:

* Stack traces
* SQL errors
* Internal filesystem paths
* Secret values
* Tokens
* Encryption metadata that should remain private
* Internal infrastructure details

Use:

User-safe error
+
Request ID

Log technical details securely server-side.

---

# 38. BROWSER SECURITY

---

Implement where applicable:

* CSP
* HSTS
* Secure cookies
* HttpOnly cookies
* SameSite protection
* Strict transport
* Referrer-Policy
* X-Content-Type-Options
* Permissions-Policy
* Trusted Types where practical
* Strict input handling
* Output encoding
* Safe HTML handling

Do not use:

* eval()
* unsafe dynamic scripts
* unnecessary inline scripts
* unsafe HTML injection
* random third-party scripts

---

# 39. CSRF / XSS / INJECTION PROTECTION

---

Explicitly protect against:

* XSS
* CSRF
* SQL injection
* command injection
* SSRF
* template injection
* path traversal
* prototype pollution
* mass assignment
* unsafe deserialization
* malicious file uploads

Use framework/library security mechanisms.

Do not roll your own sanitizers where a maintained standard library exists.

---

# 40. RATE LIMITING

---

Rate-limit at minimum:

* Login
* MFA verification
* Password recovery
* Passkey registration
* API requests
* Secret reveal
* Export
* Sharing
* Recovery
* Sensitive admin operations

Use sensible progressive throttling.

Do not create permanent lockouts that can trivially become denial-of-service tools.

---

# 41. BACKUPS

---

Backups must be:

* Encrypted
* Access-controlled
* Versioned
* Retained according to policy
* Audited
* Tested for restoration

Create an actual restore test.

A backup is not considered working until restoration has been successfully verified.

---

# 42. SECRETS MANAGEMENT

---

The password manager itself has secrets.

Never hardcode:

* Database passwords
* OAuth secrets
* JWT secrets
* Service keys
* Encryption infrastructure keys
* Storage credentials
* SMTP credentials
* Third-party API keys

Use environment secrets or a dedicated secret-management/KMS system.

Never commit .env files containing real secrets.

---

# 43. CI/CD SECURITY

---

Implement:

* Protected main branch
* Dependency lockfile
* Secret scanning
* SAST
* Dependency scanning
* Container scanning if containers are used
* Infrastructure scanning if applicable
* Unit tests
* Integration tests
* E2E tests
* Security tests
* Build verification

Do not expose production secrets to untrusted pull requests.

---

# 44. DEPENDENCY SECURITY

---

Minimize dependencies.

For every security-sensitive package:

* Verify source/project legitimacy
* Prefer established maintained projects
* Pin versions through lockfiles
* Scan vulnerabilities
* Document why it is used
* Avoid redundant crypto packages

Do not blindly install packages just because an AI-generated solution suggests them.

---

# 45. CRYPTOGRAPHY CODE RULES

---

Create a dedicated crypto service/module.

Application code must NOT contain scattered crypto primitives.

Centralize:

* KDF
* Key generation
* Encryption
* Decryption
* Key wrapping
* Key unwrapping
* Nonce generation
* Crypto serialization
* Versioning

The rest of the app should call a small, well-tested cryptographic interface.

Document every security-sensitive crypto function.

Do not alter cryptographic behavior casually.

---

# 46. CLIENT CRYPTO BOUNDARY

---

Create an explicit boundary such as:

CryptoService

with methods conceptually like:

deriveKey()
generateUserKeyPair()
generateVaultKey()
encrypt()
decrypt()
wrapVaultKey()
unwrapVaultKey()
encryptPrivateKey()
decryptPrivateKey()
encryptAttachment()
decryptAttachment()
rotateVaultKey()

The API/backend must only see encrypted representations.

---

# 47. FRONTEND STATE

---

Do not keep plaintext vault contents globally longer than necessary.

Avoid persistent plaintext state.

When possible:

* Scope decrypted state to the vault screen
* Use in-memory state
* Clear state on vault lock
* Avoid browser persistence for plaintext
* Avoid analytics instrumentation inside secret views
* Avoid error reporting of sensitive state

Do not claim guaranteed memory deletion in a garbage-collected browser runtime.

---

# 48. NO SECRET LEAKS

---

Search the entire codebase and ensure secrets cannot enter:

* console.log
* logger
* analytics
* telemetry
* error trackers
* URLs
* query strings
* localStorage
* sessionStorage
* IndexedDB plaintext stores
* DOM attributes
* HTML comments
* page titles
* browser notifications
* server logs
* database error messages
* monitoring tools

Create automated regression tests for these.

---

# 49. TESTING STRATEGY

---

Do not stop after unit tests.

Create:

A. Unit tests
B. Integration tests
C. API tests
D. Database authorization tests
E. E2E tests
F. Crypto tests
G. Property-based tests
H. Security regression tests
I. Attack simulation tests
J. Build/deployment tests

---

# 50. CRYPTO TESTS

---

Test:

* Encrypt then decrypt returns exact original
* Wrong key fails
* Modified ciphertext fails
* Modified nonce fails
* Modified associated data fails
* Wrong key version fails safely
* Random nonces are unique according to primitive requirements
* KDF behaves deterministically for identical inputs
* Different salt produces different derived keys
* Password change/rekey path works
* Vault rekey works
* Key wrapping/unwrapping works
* Unauthorized member cannot unwrap vault key
* Old revoked access material stops working where architecture permits
* Attachment encryption/decryption works
* Large-file encryption/decryption works
* Corrupted ciphertext is rejected

Use official/library-supported test vectors where available.

---

# 51. AUTH TESTS

---

Test:

* Wrong password
* Credential stuffing
* Brute-force rate limits
* MFA failure
* MFA replay
* Recovery-code replay
* Session expiration
* Refresh-token rotation
* Refresh-token reuse
* Session revocation
* Device revocation
* Passkey registration
* Passkey login
* Passkey removal
* Reauthentication
* Logout
* Global logout

---

# 52. AUTHORIZATION TESTS

---

Create automated tests for:

* Horizontal privilege escalation
* Vertical privilege escalation
* Cross-client access
* Cross-vault access
* Cross-folder access
* Cross-item access
* Cross-organization access
* IDOR/BOLA
* User removal
* Role changes
* Permission revocation
* Expired sharing links
* Temporary access expiry

For EVERY sensitive API endpoint, include at least one negative authorization test.

---

# 53. WEB SECURITY TESTS

---

Test:

* XSS
* CSRF
* SQL injection
* SSRF
* Path traversal
* Malicious file upload
* MIME confusion
* Parameter pollution
* Mass assignment
* Prototype pollution where relevant
* Open redirect
* Clickjacking where relevant
* Security-header configuration
* CSP effectiveness

---

# 54. SESSION SECURITY TESTS

---

Test:

* Session fixation
* Session hijacking
* Token replay
* Refresh-token reuse
* Expired session use
* Revoked session use
* Logout then API request
* Password change invalidating sessions where policy requires
* MFA removal invalidation
* Admin global session revocation

---

# 55. FILE SECURITY TESTS

---

Test:

* Oversized file
* Wrong MIME
* Wrong extension
* Double extension
* Executable upload
* Path traversal
* Unauthorized file download
* Expired signed URL
* Cross-user file access
* Cross-organization file access
* Malicious filename
* Corrupt encrypted file

---

# 56. DATABASE SECURITY TESTS

---

Test:

* RLS
* Tenant isolation
* Unauthorized reads
* Unauthorized writes
* Unauthorized deletes
* Organization switching attacks
* Client ID tampering
* Vault ID tampering
* Item ID tampering
* Mass assignment
* Privilege escalation

---

# 57. E2E USER FLOWS

---

Automate complete workflows:

1. Create account
2. Enable MFA
3. Register passkey
4. Set up vault
5. Create client
6. Create vault
7. Create folder
8. Add credential
9. Encrypt credential
10. Save credential
11. Close/reopen application
12. Unlock vault
13. Reveal password
14. Copy password
15. Verify clipboard clears
16. Create TOTP
17. Generate password
18. Upload encrypted attachment
19. Share vault
20. Verify recipient access
21. Revoke recipient
22. Verify access revoked
23. Invite employee
24. Assign permissions
25. Remove employee
26. Verify sessions revoked
27. Transfer ownership
28. Export securely
29. Rotate key
30. Recover account
31. Trigger lockdown
32. Restore from backup in a test environment

---

# 58. ADVERSARIAL TESTING

---

Act like an attacker.

After implementation, actively try to:

* Read another organization's item
* Read another client's item
* Read another vault
* Modify another user's credentials
* Escalate member → admin
* Bypass MFA
* Reuse expired tokens
* Replay refresh tokens
* Download another user's attachment
* Guess IDs
* Manipulate IDs
* Manipulate roles
* Manipulate client IDs
* Manipulate vault IDs
* Trigger export without permission
* Trigger recovery without permission
* Bypass temporary access expiry
* Inject scripts
* Inject SQL
* Force server-side requests
* Upload executable content
* Poison audit records
* Leak secrets into logs
* Leak secrets through API responses

Every discovered issue must become a regression test.

---

# 59. SECURITY TOOLING

---

Use appropriate tools available in the environment, such as:

* SAST
* Dependency scanning
* Secret scanning
* npm/package audit tools
* Semgrep or equivalent
* OWASP ZAP or equivalent
* Playwright
* Property-based testing
* Fuzzing where useful
* TypeScript strict mode
* Linting
* Formatting
* Test coverage

Do not claim tools were run if they were not.

---

# 60. API RESPONSE SECURITY

---

For every API endpoint:

Return only the required data.

Never return:

* plaintext secrets
* private keys
* master password material
* unnecessary crypto key material
* hidden admin metadata
* unrelated tenant data

Use explicit response schemas.

Avoid ORM serialization of entire database entities.

---

# 61. DATA CLASSIFICATION

---

Define:

PUBLIC
INTERNAL
CONFIDENTIAL
SECRET
CRITICAL_SECRET

Map fields and operations to classification.

Use stricter controls for CRITICAL_SECRET data.

---

# 62. SECURITY DOCUMENTATION

---

Create at minimum:

README.md
ARCHITECTURE.md
THREAT-MODEL.md
CRYPTOGRAPHY.md
KEY-MANAGEMENT.md
AUTH-ARCHITECTURE.md
AUTHORIZATION.md
DATA-FLOW.md
SECURITY.md
INCIDENT-RESPONSE.md
BACKUP-DISASTER-RECOVERY.md
TESTING.md
DEPLOYMENT.md

DATA-FLOW.md must include Mermaid diagrams.

Document these exact flows:

1. Account authentication
2. MFA
3. Passkey login
4. Vault unlock
5. Vault lock
6. Create credential
7. Read credential
8. Update credential
9. Delete credential
10. Sharing
11. Revocation
12. Attachment upload
13. Attachment download
14. Export
15. Recovery
16. Key rotation
17. Employee onboarding
18. Employee offboarding
19. Client offboarding
20. Lockdown mode

---

# 63. DATABASE DATA FLOW

---

Document exactly:

CLIENT
↓
API
↓
AUTHENTICATION
↓
AUTHORIZATION
↓
VALIDATION
↓
DATABASE
↓
RESPONSE

For sensitive content:

CLIENT
↓
PLAINTEXT
↓
CRYPTO SERVICE
↓
CIPHERTEXT
↓
API
↓
DATABASE
↓
CIPHERTEXT
↓
CLIENT
↓
CRYPTO SERVICE
↓
PLAINTEXT

---

# 64. UI REQUIREMENTS

---

Build a clean professional interface.

Screens:

* Login
* MFA
* Passkey setup
* Vault unlock
* Dashboard
* Clients
* Client detail
* Vaults
* Folder view
* Credential detail
* Add credential
* Edit credential
* TOTP view
* Secure note
* Attachments
* Sharing
* Team members
* Permissions
* Sessions/devices
* Audit logs
* Security dashboard
* Recovery
* Export
* Settings
* Organization settings
* Lockdown mode
* Employee onboarding/offboarding

Do not sacrifice security for visual effects.

---

# 65. HIGH-RISK UX

---

For destructive or sensitive actions:

* Clear warning
* Reauthentication
* MFA where appropriate
* Explicit confirmation
* Audit event
* Permission check
* Rate limit where appropriate

Sensitive actions include:

* Export
* Delete vault
* Delete organization
* Remove owner
* Recovery
* Key rotation
* Critical-secret reveal
* Mass credential changes
* Lockdown

---

# 66. SOFTWARE DESIGN

---

Use clean separation:

/auth
/crypto
/vault
/clients
/organizations
/users
/permissions
/sharing
/attachments
/audit
/security
/recovery
/sessions
/database
/api
/ui

Exact structure may adapt to the framework.

The critical requirement is separation of:

* Authentication
* Authorization
* Cryptography
* Persistence
* UI
* Audit
* Security policy

Do not put crypto logic directly inside random React components or API handlers.

---

# 67. TRANSACTION SAFETY

---

Sensitive multi-step operations must use database transactions where appropriate.

Examples:

* Add member + permissions
* Remove member + revoke access
* Ownership transfer
* Client offboarding
* Employee offboarding
* Key rotation metadata updates
* Export approval
* Lockdown

Avoid partially completed security operations.

---

# 68. CONCURRENCY / RACE CONDITIONS

---

Explicitly test:

* Two admins changing permissions simultaneously
* User removal during vault access
* Key rotation while a second user edits an item
* Simultaneous export requests
* Simultaneous offboarding
* Simultaneous vault deletion
* Sharing and revocation occurring at the same time

Use optimistic locking/versioning where appropriate.

---

# 69. VERSIONING

---

Version:

* Database schema
* Encryption formats
* Key versions
* Item versions
* API contracts
* Export formats

Old encrypted data must not become undecryptable merely because application code changed.

---

# 70. MIGRATIONS

---

Create safe migrations.

Never perform destructive migrations silently.

For schema changes:

* Migration
* Verification
* Backward compatibility where required
* Rollback strategy
* Data integrity test

---

# 71. LOGGING POLICY

---

Create explicit logger filters that prevent sensitive values entering logs.

Add regression tests for:

* Passwords
* API keys
* TOTP
* Private keys
* Recovery codes
* Secure notes

Search source code for logging statements involving secret fields.

---

# 72. OBSERVABILITY

---

Implement useful observability without exposing secrets.

Track:

* Errors
* Latency
* Availability
* Security events
* Rate-limit events
* Failed authentication
* Suspicious behavior

Do not send decrypted secrets to telemetry systems.

---

# 73. PERFORMANCE

---

Optimize without weakening security.

Account for:

* Argon2id cost
* Large encrypted vaults
* Attachment encryption
* Large files
* Multiple clients
* Multiple users
* Key rotation
* Search

Do not weaken Argon2id parameters merely to make login feel faster.

If performance is a problem, solve it architecturally.

---

# 74. ACCESSIBILITY

---

Build proper:

* Keyboard navigation
* Focus management
* Screen-reader labels
* Contrast
* Error messages
* Form validation
* Accessible reveal/copy controls

Security and accessibility must coexist.

---

# 75. RELEASE GATE

---

Do NOT declare the application production-ready until all of these pass:

[ ] Unit tests
[ ] Integration tests
[ ] E2E tests
[ ] Crypto tests
[ ] Authorization tests
[ ] Tenant-isolation tests
[ ] Security regression tests
[ ] Dependency scan
[ ] Secret scan
[ ] SAST
[ ] DAST where applicable
[ ] File-upload security tests
[ ] Session-security tests
[ ] Backup restoration test
[ ] Migration test
[ ] Build succeeds
[ ] Production build succeeds
[ ] No known critical/high vulnerabilities
[ ] No plaintext secrets in source
[ ] No plaintext secrets in logs
[ ] No plaintext secrets in database
[ ] No unauthorized cross-client access
[ ] No unauthorized cross-organization access
[ ] Key rotation tested
[ ] Recovery tested
[ ] Employee offboarding tested
[ ] Export protections tested
[ ] Lockdown tested

If a security-critical test fails, fix it before declaring completion.

---

# 76. FINAL CODEBASE AUDIT

---

After implementation:

Search the entire project for:

* password
* secret
* token
* apiKey
* privateKey
* recoveryCode
* masterPassword
* plaintext
* localStorage
* sessionStorage
* console.log
* logger
* dangerouslySetInnerHTML
* eval
* innerHTML
* fetch
* authorization
* role
* organizationId
* clientId
* vaultId
* itemId

Review each result manually.

Look specifically for:

* plaintext leaks
* missing authorization
* insecure storage
* insecure logging
* unsafe serialization
* accidental secret transmission
* frontend-only permissions
* predictable IDs
* missing rate limits

---

# 77. FINAL SECURITY REVIEW

---

Before final completion, behave like an independent security reviewer.

Review:

A. Architecture
B. Threat model
C. Crypto design
D. Key management
E. Authentication
F. Authorization
G. Multi-tenancy
H. API security
I. Browser security
J. Storage
K. Attachments
L. Sharing
M. Recovery
N. Export
O. Audit
P. Sessions
Q. Backups
R. CI/CD
S. Dependencies
T. Testing

Find weaknesses.

Fix them.

Then run the tests again.

---

# 78. REQUIRED FINAL OUTPUT FROM THE AGENT

---

When finished, do NOT simply say:

"Done."

Return a structured completion report containing:

1. What was built
2. Final architecture
3. Technology stack
4. Database schema
5. Authentication flow
6. Authorization flow
7. Input flow
8. Output flow
9. Data flow
10. Encryption flow
11. Decryption flow
12. Cryptographic primitives used
13. Key hierarchy
14. Key rotation process
15. Recovery process
16. Sharing process
17. Offboarding process
18. Export process
19. Threat model summary
20. Security controls
21. Tests created
22. Tests executed
23. Exact test results
24. Security tools executed
25. Vulnerabilities discovered
26. Vulnerabilities fixed
27. Remaining known limitations
28. Deployment instructions
29. Environment variables required
30. Backup procedure
31. Disaster recovery procedure
32. Files created/changed
33. Any decisions that were necessary because the repository had existing constraints

Never fabricate test results.

If something could not be tested, explicitly state:

NOT TESTED
Reason:
Risk:
Required next action:

---

# 79. HARD RULES

---

NEVER:

* Invent crypto
* Implement custom password hashing
* Use MD5
* Use SHA-1 for password security
* Use plain SHA-256 for password hashing
* Store plaintext passwords
* Store plaintext master password
* Put plaintext secrets in localStorage
* Put plaintext secrets in URLs
* Log secrets
* Send vault plaintext to the server unnecessarily
* Trust frontend authorization
* Skip tenant isolation
* Skip authorization tests
* Use Math.random() for secrets
* Hardcode production secrets
* Commit .env secrets
* Create public credential storage
* Create public attachment buckets
* Return entire ORM records blindly
* Create unrestricted plaintext CSV exports
* Disable security checks to make tests pass
* Remove tests to make the build green
* Claim a security property that the architecture does not actually provide
* Claim tests were run when they were not
* Use "TODO security" placeholders
* Leave fake/mock production credentials
* Use insecure demo crypto
* Bypass a security control because it is inconvenient

---

# 80. IMPORTANT IMPLEMENTATION PRIORITY

---

Build in this order:

1. Repository inspection
2. Architecture
3. Threat model
4. Data model
5. Authentication
6. Authorization
7. Cryptographic service
8. Key hierarchy
9. Encrypted vault storage
10. Core vault operations
11. Sessions
12. MFA/passkeys
13. Sharing
14. Attachments
15. Audit logs
16. Security dashboard
17. Recovery
18. Export
19. Offboarding
20. Key rotation
21. Lockdown
22. Security testing
23. E2E testing
24. Attack testing
25. Documentation
26. Final security audit

Do not start by polishing the UI.

Security architecture comes first.

---

# 81. DEFINITION OF DONE

---

The project is considered complete only when:

* It builds successfully
* It runs successfully
* Database migrations work
* Authentication works
* MFA works
* Passkeys work where implemented
* Vault unlock works
* Vault lock works
* Encryption works
* Decryption works
* Sharing works
* Revocation works
* Permissions work
* Attachments work
* Audit logs work
* Recovery works
* Export controls work
* Key rotation works
* Employee offboarding works
* Client offboarding works
* Lockdown works
* Backups work
* Restore works
* Security tests pass
* Cross-tenant tests pass
* Authorization tests pass
* Crypto tests pass
* E2E tests pass
* No critical/high known vulnerabilities remain
* Documentation matches actual implementation

Most importantly:

A database dump must contain ciphertext, not plaintext vault secrets.

An employee without authorization must not be able to access another client's secrets.

A normal application admin must not automatically possess the cryptographic ability to decrypt every vault.

A stolen authentication session must not automatically equal plaintext access to every vault.

A stolen database backup must not equal a plaintext credential dump.

---

# 82. FINAL INSTRUCTION

---

Do the implementation, testing, fixing, and documentation in this repository.

Do not give me a tutorial instead of implementation.

Do not give me pseudo-code instead of implementation.

Do not create a fake demo.

Do not stop after scaffolding.

Do not stop after the first successful build.

Keep iterating until the complete system and its tests are implemented.

When implementation reveals an architectural security problem, fix the architecture instead of patching around the symptom.

Use established cryptographic libraries and standard security protocols.

The final result must be a real production-oriented codebase with explicit security boundaries, explicit data flows, explicit cryptographic flows, explicit authorization, comprehensive testing, and clear documentation.

DO NOT CLAIM "SECURE" AS A GUARANTEE.

State concrete security properties, test evidence, and remaining limitations.
