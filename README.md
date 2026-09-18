# tpm-keyring-unlock

Fork of a deleted project that restores the original TPM-based GNOME Keyring unlocking tool.

Original source: https://github.com/Tunahanyrd/tpm-keyring-unlock/tree/main#

Unlock GNOME Keyring using a TPM2-sealed secret.

Small local-only CLI that unlocks the real GNOME Keyring default collection
after passwordless login, using a TPM2-sealed keyring master password.

During enrollment, the tool resolves the live default Secret Service
collection via `org.freedesktop.Secret.Service.ReadAlias("default")`, and can
still be overridden with `--collection` when you need to target a non-default
alias. The selected collection and PCR policy are stored in `metadata.json`
and reused by later `unlock` calls.

Useful when PAM cannot provide your login password to `gnome-keyring`, such as
fingerprint login, face unlock, FIDO2 login, or autologin.


It is built for this shape:

```text
Go -> godbus/dbus -> gnome-keyring
Go -> tpm2-tools  -> TPM
```

No Python helper. No plaintext password file. No password in argv, environment,
systemd unit, logs, or shell history.

## Install

Build a static binary:

```bash
CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o tpm-keyring-unlock .
sha256sum tpm-keyring-unlock > tpm-keyring-unlock.sha256
```

Run checks:

```bash
./tpm-keyring-unlock doctor
```

Enroll once:

```bash
./tpm-keyring-unlock enroll
```

Install the user service:

```bash
./tpm-keyring-unlock install
```

The service is enabled on the user `default.target`. Startup timing is handled
by the app's DBus retry loop, not by `graphical-session.target`.

## Commands

```text
tpm-keyring-unlock doctor
tpm-keyring-unlock status
tpm-keyring-unlock enroll
tpm-keyring-unlock unlock
tpm-keyring-unlock install
tpm-keyring-unlock uninstall
tpm-keyring-unlock purge
```

Useful options:

```text
--pcrs sha256:7
--timeout 30s
--collection /org/freedesktop/secrets/collection/Default_5fkeyring
--state-dir ~/.local/share/tpm-keyring-unlock
```

If `--collection` is omitted, the tool reads the active default Secret Service
alias at runtime and uses that exact object path. This avoids assuming a fixed
GNOME Keyring naming pattern on systems where the default collection has a
non-standard object path.

## What It Stores

```text
~/.local/share/tpm-keyring-unlock/keyring.pub
~/.local/share/tpm-keyring-unlock/keyring.priv
~/.local/share/tpm-keyring-unlock/metadata.json
```

`metadata.json` records the collection object path and PCR selection captured
during enrollment. `unlock` uses those values instead of resolving the current
`default` alias or taking PCR settings from its command line.

`enroll` immediately self-tests the sealed object by unsealing it again. If the
self-test fails, generated state files are removed.

## Doctor

`doctor` checks:

- required `tpm2-tools`
- TPM access and PCR 7 reads
- DBus session bus access
- `org.freedesktop.secrets`
- default collection lock-state property
- state file permissions

If `/dev/tpmrm0` is group-writable but your user is not in that actual device
group, `doctor` prints the owner/group, your groups, and this kind of fix:

```bash
sudo usermod -aG <actual-device-group> <your-username>
```

It uses the device's actual group, not a hardcoded group name. Then fully log
out of the graphical session and log back in, or reboot. Opening a new shell is
not enough for group membership changes. The tool never runs that command for
you.

## Systemd

`install` writes:

```text
~/.config/systemd/user/tpm-keyring-unlock.service
```

The unit runs:

```text
tpm-keyring-unlock unlock
```

`uninstall` stops and disables the user service, removes the unit file, and runs
`systemctl --user daemon-reload`.

`purge` removes the sealed state files only. It does not stop or disable the
user service, remove its unit file, or modify GNOME Keyring contents or
passwords. Run `uninstall` separately when the systemd user service should be
removed.

## Security Model

This tool stores the GNOME Keyring master password only as a TPM2-sealed object.

The password is not stored in plaintext on disk.

The password is not passed via:

- argv
- environment variables
- shell history
- systemd unit files

If TPM unseal succeeds, the keyring is unlocked automatically.

This means that any process running as the logged-in user may access secrets
that are normally available through an unlocked GNOME Keyring.

This tool improves usability for passwordless login setups. It does not provide
stronger protection than a locked user session.

## TPM Notes

The sealed object is created under the TPM owner hierarchy:

```text
tpm2_createprimary -C o
```

This is the ordinary choice for user-owned sealed objects on a local machine:
the tool does not need endorsement keys, platform authorization, or LUKS slot
changes.

The object is created with a PCR policy digest and the `adminwithpolicy`/fixed
TPM/fixed parent attributes, so it can only be unsealed when the same PCR state
is present. The flow uses:

```text
tpm2_startauthsession
 tpm2_policypcr
 tpm2_flushcontext
 tpm2_create -L <policyDigest> -a fixedtpm|fixedparent|adminwithpolicy
```

This intentionally removes the normal `userwithauth` path; the secret is
available only when the session satisfies the recorded PCR policy.

The default PCR policy is `sha256:7`, matching Secure Boot state. That is
intentionally less fragile than sealing to PCRs that change across normal kernel
or initramfs updates.

Some machines may have custom TPM hierarchy policies or restricted owner
hierarchy access. In that case `doctor` should show the TPM access failure, and
you may need to adapt the hierarchy/policy for that system.

## GNOME Keyring Note

This tool uses GNOME Keyring's private DBus method:

```text
org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.UnlockWithMasterPassword
```

That is the largest compatibility risk. It is used because the public
`gnome-keyring-daemon --unlock` path can target the wrong `login` alias on
systems where the real default collection has a different object path.

## Release Build

The GitHub workflow publishes static Linux binaries for:

- linux-amd64
- linux-arm64

along with SHA256 checksums.

The local equivalent is:

```bash
CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o tpm-keyring-unlock .
sha256sum tpm-keyring-unlock > tpm-keyring-unlock.sha256
```
