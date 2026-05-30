# tpm-keyring-unlock

Unlock GNOME Keyring using a TPM2-sealed secret.

Small local-only CLI that unlocks the real GNOME Keyring default collection
after passwordless login, using a TPM2-sealed keyring master password.

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

## What It Stores

```text
~/.local/share/tpm-keyring-unlock/keyring.pub
~/.local/share/tpm-keyring-unlock/keyring.priv
~/.local/share/tpm-keyring-unlock/secret.sha256
~/.local/share/tpm-keyring-unlock/metadata.json
```

`secret.sha256` is only an integrity check. It cannot unlock the keyring.

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
sudo usermod -aG <actual-device-group> $USER
```

Then log out and log back in. The tool never runs that command for you.

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

`purge` removes the sealed state files. It does not uninstall the service, and
it does not modify GNOME Keyring contents or passwords.

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
