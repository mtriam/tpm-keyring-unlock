# tpm-keyring-unlock

Small local-only CLI that unlocks the real GNOME Keyring default collection
after passwordless login, using a TPM2-sealed keyring master password.

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

`purge` removes the sealed state files. It does not uninstall the service.

## Release Build

The GitHub workflow builds a Linux amd64 static binary and publishes a SHA256
checksum artifact. The local equivalent is:

```bash
CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o tpm-keyring-unlock .
sha256sum tpm-keyring-unlock > tpm-keyring-unlock.sha256
```
