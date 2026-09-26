# tpm-keyring-unlock

Fork of a deleted project that restores the original TPM-based GNOME Keyring
unlocking tool.

Original source:
https://github.com/Tunahanyrd/tpm-keyring-unlock/tree/main

<details>

<summary><strong>🔍 Differences from the original</strong></summary>

Here, “the original” means the initial public-release state from which this
fork started, commit `19bcc53` (“Initial public release”).

This fork keeps the original goal and GNOME Keyring integration, but significantly
changes the TPM, collection-discovery, enrollment-metadata, and state-management
design compared with that baseline.

Main differences:

- Replaces filesystem TPM state (`keyring.pub`, `keyring.priv`, and
  `secret.sha256`) with a sealed object stored persistently in the TPM.
- On the author's system, unlock time improved from approximately 2.5 seconds
  in the initial version to approximately 0.2 seconds with this fork. Actual
  performance depends on the TPM, system configuration, and session timing.
- Adds configurable persistent-handle support, automatic allocation of a free
  handle when the default is occupied, and protection against overwriting an
  unrelated TPM object.
- Stores the persistent object's TPM Name and verifies it before unlock, status,
  purge, or removal, preventing a foreign object from being trusted by handle
  alone.
- Replaces the hardcoded collection path with runtime lookup via Secret Service `ReadAlias("default")`.
- Records and validates enrollment metadata, including the selected collection,
  PCR policy, persistent handle, and TPM object Name.
- Encrypts the keyring password with a random per-enrollment AES-256-GCM key
  before sealing the ciphertext into the TPM; the wrapping key and nonce are
  stored in protected local metadata.
- Adds explicit PCR-policy construction and verification, with stricter checks
  for PCR selections, handles, D-Bus paths, metadata, and protected state.
- Adds transactional enrollment, TPM self-tests, rollback, atomic metadata
  writes, and safer purge behavior for missing, foreign, or stale state.
- Extends `status` and `doctor` with persistent-object identity, PCR, D-Bus,
  Secret Service, systemd, permissions, and handle-availability diagnostics.
- Adds a permanent Go test suite covering security-sensitive validation and
  state management, plus `build.sh` for formatting, tests, and static builds.
- Expands release automation from the initial single Linux amd64 artifact to
  Linux amd64 and arm64 binaries with checksums.

The actual performance improvement depends on the TPM, system configuration,
GNOME Keyring startup timing, and other local factors.

The GNOME Keyring integration and the original purpose of the project remain
unchanged.

</details>


Unlock GNOME Keyring using a TPM2-sealed secret.

Small local-only CLI that unlocks the real GNOME Keyring default collection
after passwordless login, using a TPM2-sealed, AES-GCM-encrypted keyring master
password.

During enrollment, the tool resolves the live default Secret Service
collection via `org.freedesktop.Secret.Service.ReadAlias("default")`.
The selected collection and PCR policy are stored in `metadata.json` and
reused by later `unlock` calls.

The sealed TPM object is stored persistently in the TPM under a configurable
persistent handle. Enrollment uses this handle by default:

    0x81018043

If the default handle is occupied, enrollment automatically selects the first
free handle in `0x81018000 .. 0x8101ffff`. Supplying `--handle` disables this
automatic selection and keeps the requested handle explicit.

The tool stores the TPM object's Name in `metadata.json` and verifies that the
object currently occupying the configured handle is the same object that was
enrolled. This prevents an unrelated TPM object from being used merely because
it occupies the expected handle.

Useful when the login password is not available to `gnome-keyring`, including
fingerprint login, face unlock, FIDO2 login, autologin, or session setups where
the user's graphical session is started directly without passing the login
password to `pam_gnome_keyring`.

It is built for this shape:

    Go -> godbus/dbus -> gnome-keyring
    Go -> tpm2-tools  -> TPM

No Python helper. No plaintext password file. No password in argv, environment,
systemd unit, logs, or shell history.

## Summary

### Recent changes

- Encrypts the password with a random per-enrollment AES-256-GCM key before sealing; TPM stores ciphertext, while `metadata.json` stores the wrapping key and nonce.
- Decrypts and authenticates the unsealed value during unlock, and verifies the plaintext in both enrollment self-tests.
- Bumps metadata format from version 5 to 6; existing enrollments need `purge` followed by `enroll` before reuse.
- Validates the wrapping key and nonce and adds tests for round-trip encryption, wrong keys, and tampered ciphertext.
- Expands `doctor` security notes to explain that wrapping does not protect against a local process with access to both metadata and TPM, and that deleting metadata leaves the TPM handle occupied until `purge`.


<details>
<summary><strong>🔍 Alternative project: dmitriitimoshenko/tpm-keyring-unlock</strong></summary>

There is another project with the same general goal:

https://github.com/dmitriitimoshenko/tpm-keyring-unlock

That project follows a different architecture.

This repository:

- does not modify PAM;
- runs as a user systemd service;
- communicates with GNOME Keyring through the Secret Service D-Bus interface;
- retrieves the sealed keyring password from a persistent TPM object;
- verifies the TPM object's Name before using it;
- unlocks the already-running GNOME Keyring collection.

The alternative project integrates directly with the PAM authentication stack:

- provides a PAM module named `pam_tpm_keyring_authtok.so`;
- unseals the keyring password during PAM authentication;
- provides it through `PAM_AUTHTOK` for `pam_gnome_keyring.so`;
- modifies PAM configuration during installation;
- also addresses a systemd/PAM race involving `gnome-keyring-daemon.service`;
- is specifically designed around fingerprint authentication and related
  passwordless login scenarios.

The two projects therefore solve a similar problem at different layers:

    This repository:
    login -> systemd user service -> Secret Service D-Bus -> GNOME Keyring

    Alternative project:
    login -> PAM -> TPM PAM module -> PAM_AUTHTOK -> pam_gnome_keyring

See the alternative project for its full PAM integration and authentication
stack requirements:

https://github.com/dmitriitimoshenko/tpm-keyring-unlock

</details>


## Install

Install the required build, Git, and TPM tools:

**Arch Linux:**

    sudo pacman -S --needed git go tpm2-tools gnome-keyring

**Debian/Ubuntu:**

    sudo apt update
    sudo apt install -y git golang-go tpm2-tools gnome-keyring


The system also needs:

    systemd
    D-Bus

Clone the repository:

    git clone https://github.com/mtriam/tpm-keyring-unlock.git
    cd tpm-keyring-unlock

Build and test:

    ./build.sh

The build script formats the Go source, runs the test suite, and builds the
static release binary.

For `install`, use a permanent binary path. The binary itself must be a
non-symlinked executable regular file owned either by `root` or by the current
user. Every parent directory on that path must be non-symlinked and not
writable by group or others.

Run environment checks:

    ./tpm-keyring-unlock doctor

Enroll the GNOME Keyring once:

    ./tpm-keyring-unlock enroll

Install the user service:

    ./tpm-keyring-unlock install

The service is enabled on the user `default.target`. Startup timing is handled
by the application's D-Bus retry loop, not by `graphical-session.target`.

To verify the resulting configuration:

    ./tpm-keyring-unlock status

## Troubleshooting

### Persistent TPM handle is already occupied

By default, the tool uses persistent TPM handle:

    0x81018043

If this handle is already occupied by another TPM object, automatic enrollment
will select a free handle from `0x81018000 .. 0x8101ffff`; it will never
overwrite or remove the existing object.

Check the persistent TPM handles:

    tpm2_getcap handles-persistent

Normally no action is needed: `enroll` automatically uses the first free
handle in the allocation range. To choose the handle yourself, pass
`--handle` with a free handle, for example:

    ./tpm-keyring-unlock enroll -handle 0x81018044

This creates a fresh enrollment in the requested free TPM persistent handle.
The requested handle must not already be present in `tpm2_getcap
handles-persistent`.

Or, if the existing object belongs to this application, remove the enrollment
first:

    ./tpm-keyring-unlock purge

Then enroll again:

    ./tpm-keyring-unlock enroll

The application verifies the TPM object's Name before using or removing a
persistent object. It will refuse to remove an object that cannot be verified
as belonging to this enrollment.

If you are unsure who owns an existing persistent handle, do not remove it.
Automatic allocation will leave it untouched and use another free handle.

To inspect the current enrollment and TPM object state:

    ./tpm-keyring-unlock status

For additional environment and TPM diagnostics:

    ./tpm-keyring-unlock doctor

### Removing a leftover TPM object manually

If the application state and `metadata.json` are no longer available, but the
persistent TPM object remains, it can be removed directly with `tpm2-tools`.

First check which persistent handles are currently in use:

    tpm2_getcap handles-persistent

If the leftover object is confirmed to be the one previously used by
`tpm-keyring-unlock`, remove it with:

    tpm2_evictcontrol -C o -c 0x81018043

Replace `0x81018043` with the actual persistent handle if a different handle
was configured.

Verify that the handle is no longer present:

    tpm2_getcap handles-persistent

**Do not run `tpm2_evictcontrol` against an unknown handle.** A persistent TPM
handle may belong to another application or system component. If the original
`metadata.json` is still available, prefer:

    ./tpm-keyring-unlock status
    ./tpm-keyring-unlock purge

because the application verifies the TPM object's Name before removing it.

## Commands

    tpm-keyring-unlock doctor
    tpm-keyring-unlock status
    tpm-keyring-unlock enroll
    tpm-keyring-unlock unlock
    tpm-keyring-unlock install
    tpm-keyring-unlock uninstall
    tpm-keyring-unlock purge

Useful options:

    -pcrs sha256:7
    -timeout 30s
    -collection /org/freedesktop/secrets/collection/login
    -state-dir ~/.local/share/tpm-keyring-unlock
    -handle 0x81018043

The built-in help and the program's canonical examples use single-dash flags
such as `-pcrs` and `-handle`. The Go flag parser also accepts the common
`--flag` form on most systems, but the single-dash form matches the CLI help
output exactly.

`-handle` selects the TPM persistent handle used for the sealed object.
The default is `0x81018043`.

Persistent handles are TPM-wide, not per-user. If multiple users on the same
machine use this program, they must use different persistent handles and
separate state directories.

The persistent handle must be inside the TPM owner persistent-handle range used
by `tpm2_evictcontrol -C o`:

    0x81000000 .. 0x817fffff

The platform-controlled half of the global persistent range
(`0x81800000 .. 0x81ffffff`) is intentionally rejected.

If `--collection` is omitted, the tool reads the active default Secret Service
alias at runtime and uses that exact object path. This avoids assuming a fixed
GNOME Keyring naming pattern on systems where the default collection has a
different object path.

The collection and PCR selection used during enrollment are stored in
`metadata.json`. Later `unlock` operations use the stored values rather than
silently replacing them with current command-line defaults.


## Enrollment

Run:

    ./tpm-keyring-unlock enroll

Enrollment performs the following high-level sequence:

    validate tpm2-tools and configuration
    validate PCR selection
    validate the persistent TPM handle
    resolve/validate the Secret Service collection
    check the TPM
    verify state directory permissions
    check that enrollment does not already exist
    check that the selected TPM persistent handle is unused
    read the GNOME Keyring master password
    verify the password against the selected collection
    generate a random AES-256-GCM key and nonce
    encrypt the password; pass only the ciphertext to the TPM
    create the TPM primary object
    create a PCR policy
    create the sealed object
    load and self-test the sealed object
    make the sealed object persistent
    read and store its TPM Name
    self-test the persistent object
    atomically write metadata

The application explicitly zeroes its plaintext and raw wrapping-key buffers
after use where possible. Go cannot guarantee that temporary runtime or
serialization copies are erased. The ciphertext is sealed into the TPM;
`metadata.json` stores the wrapping key and nonce needed to recover it after
unseal.

Metadata version 6 adds these wrapping fields. Existing enrollments with an
older metadata version must be removed with `purge` and created again with
`enroll`; they cannot be unlocked by this version.

The enrollment refuses to overwrite an existing enrollment. To create a new
enrollment, purge the existing enrollment first.

If an enrollment step fails after the persistent TPM object has been created,
the program attempts to remove that newly-created object again so that a
partial enrollment is not normally left behind.


## What It Stores

The local state directory is:

    ~/.local/share/tpm-keyring-unlock/

The current enrollment stores:

    metadata.json

The encrypted secret is sealed in the TPM. Temporary TPM creation files are
used during enrollment and removed afterwards; no sealed key files are kept
in the state directory.

`metadata.json` contains information such as:

    metadata version
    application identifier
    creation time
    Secret Service collection object path
    PCR selection
    persistent TPM handle
    TPM object Name
    AES-256-GCM wrapping key (hex encoded)
    AES-GCM nonce (hex encoded)

The plaintext GNOME Keyring master password is not stored in `metadata.json`.
The wrapping key is stored there, so metadata alone is not a password vault;
the corresponding ciphertext remains sealed in the TPM.

The TPM Name is used to verify that the object currently present at the
configured persistent handle is the same object that was enrolled.

The state directory must be owned by the current user and have mode `0700`.
Metadata must have mode `0600`. Symlinks are not accepted for protected state
files.

## Security Model

Only the AES-GCM ciphertext is sealed in the TPM. The plaintext keyring master
password is recovered in process memory during unlock. `metadata.json` does not
contain the plaintext password, but it does contain the wrapping key and nonce
needed to decrypt the sealed ciphertext.

Wrapping does not protect against a process that can read `metadata.json` and
use the TPM while the enrolled PCR state matches. The TPM policy has no PIN or
`authValue`; it is based on PCRs only. A process running as the same user can
normally read the metadata and access `/dev/tpmrm0`.

The PCR policy is intended to prevent recovery from a disk-only copy without
access to the enrolled TPM in the matching measured-boot state. It does not
protect against a compromised session, root access, or a process able to use
the TPM while the policy is satisfied. After unlock, processes running as the
logged-in user can access secrets available through the unlocked keyring.

The password is read interactively, not passed through argv, environment
variables, shell history, systemd unit files, or logs. The application zeroes
sensitive byte buffers after use where possible, but Go cannot guarantee that
all temporary runtime or serialization copies are erased.

Unlock uses GNOME Keyring's private, unsupported D-Bus interface. The Secret
Service session used here is not encrypted on the session bus.

Deleting `metadata.json` removes the local wrapping key, leaving the TPM-sealed
ciphertext unrecoverable through the normal application flow. This is
cryptographic erasure only if every copy of the metadata is gone; backups and
snapshots retain the key. Deleting the metadata does not evict the persistent
TPM object; use `purge` to remove it and free its handle.


## TPM Persistent Object

The sealed object is stored persistently in the TPM.

By default:

    0x81018043

The object is created under the TPM owner hierarchy:

    tpm2_createprimary -C o

After creation and testing, the sealed object is made persistent using the
configured handle.

The tool records the object's TPM Name in `metadata.json`.

Before using or removing the persistent object, the program compares the
current TPM Name with the stored Name.

The following states are distinguished:

    absent
    present, Name verified
    present, but a DIFFERENT object (Name mismatch)
    present, identity unverified (no stored Name)

An object is only automatically removed by `purge` when its identity can be
verified as belonging to this enrollment.

This is important because TPM persistent handles are not exclusive to this
program. An unrelated object could otherwise occupy the same handle.


## PCR Policy

The default PCR policy is:

    sha256:7

PCR selections can be changed during enrollment, for example:

    --pcrs sha256:7

Supported PCR banks are:

    sha1
    sha256
    sha384
    sha512

PCR indexes must be in the range:

    0 .. 23

Bank names are case-insensitive, so for example:

    SHA256:7

is accepted.

The PCR selection syntax is validated before TPM operations are performed.
Duplicate banks, duplicate PCR indexes, malformed selections, whitespace,
unsupported banks, and indexes outside the supported range are rejected.

The policy flow uses a trial policy session and `tpm2_policypcr` to construct
the policy digest used by the sealed object.

Conceptually:

    tpm2_startauthsession
    tpm2_policypcr
    tpm2_flushcontext
    tpm2_create

The sealed object requires the configured PCR policy for unsealing.

The default `sha256:7` policy is intended to bind the secret to the machine's
Secure Boot-related PCR state without tying it to PCRs that commonly change
during normal kernel or initramfs updates.

Changing the PCR state can make an existing enrollment unusable.

For example, changing Secure Boot state can change PCR 7. In that situation,
the existing TPM policy may no longer match and the secret cannot be
unsealed.

If the machine's PCR state intentionally changes, a new enrollment may be
required.


## Unlock

Run:

    ./tpm-keyring-unlock unlock

The unlock sequence first checks whether the selected GNOME Keyring collection
is already unlocked.

If it is already unlocked, the program exits without performing unnecessary
TPM unseal operations.

If it is locked, the program:

    reads and validates enrollment metadata
    verifies the configured persistent TPM object
    checks its TPM Name
    unseals the keyring password using the PCR policy
    zeroes the recovered password after use
    unlocks the collection
    verifies the resulting lock state

D-Bus startup races are handled by the application's retry loop.


## Secret Service Collection

The default collection is discovered through:

    org.freedesktop.Secret.Service.ReadAlias("default")

This means the program does not assume that the default collection has a
particular hardcoded object path.

For example, a system may use:

    /org/freedesktop/secrets/collection/login

instead of an older or distribution-specific path.

A collection can also be explicitly selected:

    --collection /org/freedesktop/secrets/collection/login

The selected collection is stored in metadata during enrollment and is reused
by later `unlock` operations.

The collection path is validated before it is used.


## GNOME Keyring Note

This tool uses GNOME Keyring's private D-Bus method:

    org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.UnlockWithMasterPassword

That is the largest compatibility risk.

The private interface is used because the public
`gnome-keyring-daemon --unlock` path can target a different keyring collection
on systems where the actual default collection has a different object path.

The tool therefore operates directly against the selected Secret Service
collection object.


## Purge

Run:

    ./tpm-keyring-unlock purge

`purge` removes the enrollment.

Because the sealed object is stored persistently in the TPM, purge does more
than remove local files.

When valid enrollment metadata exists, the program:

    reads and validates metadata
    verifies the configured TPM handle
    checks the current TPM object
    compares its TPM Name with the stored Name
    removes the persistent object only when its identity is verified
    removes the enrollment metadata

The program refuses to remove an object when the handle contains a different
object or when its identity cannot be verified.

This protection is intentional. A persistent TPM handle is TPM-wide and may
contain an object belonging to something other than this program.

If the TPM object was manually removed outside the program, for example with:

    sudo tpm2_evictcontrol -C o -c 0x81018043

the local metadata can become stale. In that situation the enrollment state
must be cleaned up before creating a new enrollment.

`purge` does not:

    stop or disable the user service
    remove the systemd unit
    modify GNOME Keyring contents
    change the GNOME Keyring password

Run `uninstall` separately when the systemd user service should also be
removed.


## Status

Run:

    ./tpm-keyring-unlock status

`status` reports information about:

    state directory
    enrollment metadata
    persistent TPM handle
    persistent TPM object state
    TPM Name verification
    state-file permissions
    Secret Service collection lock state
    systemd user service

The persistent object is classified separately as absent, verified, foreign,
or unverified when enough information is available.


## Doctor

Run:

    ./tpm-keyring-unlock doctor

`doctor` checks the local environment required by the program, including:

    required tpm2-tools
    TPM device access
    TPM properties
    configured PCR selection and PCR reads
    D-Bus session bus access
    org.freedesktop.secrets
    Secret Service collection access
    collection lock state
    state directory permissions
    systemd availability
    available persistent TPM handle slots

The TPM tool checks include commands needed by the current persistent-object
and PCR-policy workflow.

To inspect an orphaned persistent handle when local metadata is missing, pass
the handle explicitly to `purge`; the command will warn without evicting an
object whose identity cannot be verified:

    ./tpm-keyring-unlock purge -handle 0x81018044

If `/dev/tpmrm0` is group-writable but your user is not in that actual device
group, `doctor` prints the owner/group, your groups, and this kind of fix:

    sudo usermod -aG <actual-device-group> <your-username>

It uses the device's actual group, not a hardcoded group name.

Then fully log out of the graphical session and log back in, or reboot.
Opening a new shell is not enough for group membership changes.

The tool never runs that command for you.


## Systemd

`install` writes:

    ~/.config/systemd/user/tpm-keyring-unlock.service

The unit runs:

    tpm-keyring-unlock unlock

The service is enabled on the user `default.target`.

Startup timing is handled by the application's D-Bus retry loop rather than
depending on `graphical-session.target`.

`uninstall` stops and disables the user service, removes the unit file, and
runs:

    systemctl --user daemon-reload

`purge` and `uninstall` are separate operations.

Use `purge` to remove the TPM enrollment.

Use `uninstall` to remove the systemd user service.


## TPM Security Notes

The sealed object is created under the TPM owner hierarchy:

    tpm2_createprimary -C o

The tool does not require:

    endorsement-key enrollment
    platform authorization
    LUKS slot changes

The sealed object uses a PCR policy rather than the normal password-based
`userwithauth` authorization path.

The policy is constructed using the selected PCR bank and indexes.

The persistent object itself is identified by its TPM Name. The Name is not a
user-chosen label; it is derived from the TPM object's public area and provides
an identity that can be checked later.

A persistent TPM handle is TPM-wide. It is not automatically isolated by Linux
user account.

If multiple users or applications need persistent objects on the same TPM,
they must use different persistent handles.


## Secure Boot and PCR 7

The default policy uses:

    sha256:7

PCR 7 commonly reflects Secure Boot-related state.

Because the TPM policy is tied to the PCR value recorded during enrollment,
changing the relevant boot/security configuration can invalidate the existing
policy.

For example:

    enroll with Secure Boot enabled
    -> PCR 7 value A
    -> unlock works

Changing Secure Boot state can produce:

    PCR 7 value B
    -> existing policy does not match
    -> unlock fails

Restoring the previous Secure Boot state does not necessarily make an already
created TPM policy usable again in every transition scenario. If the current
PCR state no longer matches the state captured by the existing enrollment, a
new enrollment may be required.

This is expected TPM policy behavior, not a password mismatch.


## File and State Protection

The state directory is required to be:

    0700

Protected metadata is required to be:

    0600

The program checks ownership and rejects protected state paths that are
symbolic links.

Metadata is written using a temporary file followed by an atomic rename and
directory synchronization.

The purpose is to reduce the chance of leaving a partially-written metadata
file after a crash or interrupted write.


## Error Handling and Safety

The program deliberately refuses to perform several potentially dangerous
operations when object identity cannot be established.

In particular, `purge` will not automatically evict a persistent TPM object
merely because it happens to occupy the configured handle.

The program distinguishes:

    handle absent
    handle contains the enrolled object
    handle contains a different object
    handle contains an object whose identity cannot be verified

This prevents a stale or foreign TPM object from being treated as the
program's own sealed secret.


## Development

Build and test the project using the included build script:

    ./build.sh

The script:

    1. formats `main.go` and `main_test.go`
    2. runs `go test ./...`
    3. builds a static release binary with `CGO_ENABLED=0`
    4. disables VCS metadata with `-buildvcs=false`
    5. uses `-trimpath` and stripped linker flags

The resulting binary is:

    ./tpm-keyring-unlock

The repository contains permanent unit tests in `main_test.go` covering the
security-critical validation and state-management code.


## Release Build

The recommended local release build is:

    ./build.sh

To generate a SHA256 checksum after building:

    sha256sum tpm-keyring-unlock > tpm-keyring-unlock.sha256

The GitHub workflow publishes static Linux binaries for:

    linux-amd64
    linux-arm64

along with SHA256 checksums.

The local equivalent is:

    CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o tpm-keyring-unlock .

    sha256sum tpm-keyring-unlock > tpm-keyring-unlock.sha256
