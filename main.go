//go:build linux

// tpm-keyring-unlock: TPM2 sealed GNOME keyring unlock helper.
//
// The keyring master password is sealed into a persistent TPM object whose
// policy is a PCR policy. At login a systemd user service unseals it and
// unlocks the default Secret Service collection.
//
// Threat model (see also "doctor"):
//   - protects against offline disk theft and against changes to the selected
//     measured boot state;
//   - does NOT protect against a process that can use /dev/tpmrm0 while the
//     PCRs match, because the policy has no authValue/PIN.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	appName                = "tpm-keyring-unlock"
	serviceName            = "tpm-keyring-unlock.service"
	retryTimeout           = 30 * time.Second
	retryInterval          = 500 * time.Millisecond
	defaultSealedHandle    = "0x81018043"
	dynamicHandleFirst     = uint64(0x81018000)
	dynamicHandleLast      = uint64(0x8101ffff)
	metadataVersion        = 5
	maxSealedSecretSize    = 128
	maxPasswordInput       = 4096
	unsealBufferSize       = 2048
	maxDBusObjectPath      = 255
	maxPCRIndex            = 23
	maxMetadataSize        = 64 * 1024
	externalCommandTimeout = 30 * time.Second
	statusTimeout          = 3 * time.Second

	// Errors that are neither classified as transient nor permanent are
	// retried only this many times, so that e.g. a wrong password does not
	// keep retrying for the whole timeout.
	maxUnclassifiedAttempts = 3

	secretServiceName      = "org.freedesktop.secrets"
	secretServicePath      = "/org/freedesktop/secrets"
	privateUnlockInterface = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
)

// TPM 2.0 persistent handle ranges: the owner hierarchy may use
// 0x81000000..0x817FFFFF, the platform hierarchy 0x81800000..0x81FFFFFF.
// This tool persists with the owner hierarchy (-C o).
const (
	persistentOwnerFirst uint64 = 0x81000000
	persistentOwnerLast  uint64 = 0x817fffff
)

var handleRE = regexp.MustCompile(`^0x[0-9a-fA-F]{8}$`)

var pcrBankNames = map[string]struct{}{
	"sha1":   {},
	"sha256": {},
	"sha384": {},
	"sha512": {},
}

// Only root-owned tools from these directories are executed. PATH from the
// environment is never consulted.
var trustedToolDirs = []string{
	"/usr/local/sbin",
	"/usr/local/bin",
	"/usr/sbin",
	"/usr/bin",
	"/sbin",
	"/bin",
}

var toolCache = map[string]string{}

var errInterrupted = errors.New("interrupted")

type config struct {
	dir            string
	pcrs           string
	pcrsExplicit   bool
	collection     string
	timeout        time.Duration
	installPath    string
	systemdPath    string
	metadata       string
	handle         string
	handleExplicit bool
	forgetMetadata bool
}

type metadata struct {
	Version    int       `json:"version"`
	App        string    `json:"app"`
	CreatedAt  time.Time `json:"created_at"`
	Collection string    `json:"collection"`
	PCRs       string    `json:"pcrs"`

	// Handle is the persistent TPM handle of the sealed object.
	Handle string `json:"handle"`

	// HandleName is the TPM Name of the persistent sealed object.
	// It is used to verify that the persistent handle still refers to
	// the object enrolled by this tool.
	HandleName string `json:"handle_name"`
}

type secretValue struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// handleStatus describes what currently lives at a persistent handle
// relative to the object recorded at enrollment.
type handleStatus int

const (
	handleAbsent handleStatus = iota
	handleOurs
	handleForeign
	handleUnverified
)

func (s handleStatus) String() string {
	switch s {
	case handleAbsent:
		return "absent"
	case handleOurs:
		return "present, Name verified"
	case handleForeign:
		return "present, but a DIFFERENT object (Name mismatch)"
	case handleUnverified:
		return "present, identity unverified (no stored Name)"
	default:
		return "unknown"
	}
}

func main() {
	hardenProcess()

	err := run(os.Args)

	if err != nil {
		fmt.Fprintln(os.Stderr, colorizeStderr("error:", colorRed), err)
	}

	switch {
	case err != nil && (interrupted() || errors.Is(err, errInterrupted)):
		os.Exit(130)
	case err != nil:
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := defaultConfig()
	if err != nil {
		return err
	}

	if len(args) < 2 {
		usage()
		return nil
	}

	cmd := args[1]

	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		usage()
		return nil
	}

	switch cmd {
	case "enroll", "unlock", "status", "install", "uninstall", "purge", "doctor":
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(
		&cfg.dir,
		"state-dir",
		cfg.dir,
		"state directory",
	)

	fs.StringVar(
		&cfg.pcrs,
		"pcrs",
		cfg.pcrs,
		"PCR selection",
	)

	fs.StringVar(
		&cfg.collection,
		"collection",
		cfg.collection,
		"Secret Service collection object path",
	)

	fs.DurationVar(
		&cfg.timeout,
		"timeout",
		cfg.timeout,
		"DBus retry timeout",
	)

	fs.StringVar(
		&cfg.handle,
		"handle",
		cfg.handle,
		"persistent TPM handle for the sealed object (enroll)",
	)

	fs.StringVar(
		&cfg.installPath,
		"install-path",
		cfg.installPath,
		"absolute path of the binary referenced by the systemd unit (install)",
	)

	fs.BoolVar(
		&cfg.forgetMetadata,
		"forget-metadata",
		false,
		"purge: delete only the local state files, never touch the TPM",
	)

	if err := fs.Parse(args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return nil
		}

		return fmt.Errorf(
			"%w (run '%s help' for usage)",
			err,
			appName,
		)
	}

	if fs.NArg() > 0 {
		return fmt.Errorf(
			"unexpected arguments: %s",
			strings.Join(fs.Args(), " "),
		)
	}

	timeoutExplicit := false

	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "pcrs":
			cfg.pcrsExplicit = true
		case "handle":
			cfg.handleExplicit = true
		case "timeout":
			timeoutExplicit = true
		}
	})

	if err := validateCommandFlags(cmd, fs); err != nil {
		return err
	}

	if cmd == "status" && !timeoutExplicit {
		cfg.timeout = statusTimeout
	}

	cfg.refreshPaths()

	switch cmd {
	case "enroll", "unlock", "install", "uninstall", "purge":
		installSignalHandler()
	}

	// Only enroll needs the default collection up front. status, install and
	// purge do not need it, unlock takes it from the metadata, and doctor
	// must keep working when the Secret Service is down.
	if cmd == "enroll" && cfg.collection == "" {
		cfg.collection, err = readDefaultCollection()
		if err != nil {
			return err
		}
	}

	switch cmd {
	case "enroll":
		return enroll(cfg)

	case "unlock":
		return unlock(cfg)

	case "status":
		return status(cfg)

	case "install":
		return install(cfg)

	case "uninstall":
		return uninstall(cfg)

	case "purge":
		return purge(cfg)

	case "doctor":
		return doctor(cfg)

	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usage() {
	fmt.Printf(`%[1]s: TPM2 sealed GNOME keyring unlock helper

Usage:
  %[1]s enroll    [-pcrs sha256:7] [-handle %[2]s] [-collection PATH] [-timeout 30s] [-state-dir DIR]
  %[1]s unlock    [-collection PATH] [-timeout 30s] [-state-dir DIR]
  %[1]s status    [-timeout 3s] [-state-dir DIR]
  %[1]s install   [-install-path /absolute/path/to/binary] [-timeout 30s] [-state-dir DIR]
  %[1]s uninstall
  %[1]s purge     [-handle 0xHANDLE] [-forget-metadata] [-state-dir DIR]
  %[1]s doctor    [-pcrs sha256:7] [-collection PATH] [-state-dir DIR]

Enrollment is persistent-only. There is no sealed-file fallback.

When -handle is omitted and the default handle %[2]s is occupied, enroll
selects the first free handle in 0x81018000..0x8101FFFF. An explicitly
supplied -handle is never replaced automatically.

To replace an existing enrollment:
  %[1]s purge
  %[1]s enroll

For purge, -handle is only used to check occupancy when enrollment metadata
is absent; it never selects a different object for removal.

If purge refuses because the local metadata is unreadable or invalid, and the
TPM object is not needed (or is already gone):
  %[1]s purge -forget-metadata

`, colorize(appName, colorBold), defaultSealedHandle)
}

func validateCommandFlags(cmd string, fs *flag.FlagSet) error {
	allowed := map[string]map[string]bool{
		"enroll":    {"state-dir": true, "pcrs": true, "collection": true, "timeout": true, "handle": true},
		"unlock":    {"state-dir": true, "collection": true, "timeout": true},
		"status":    {"state-dir": true, "timeout": true},
		"install":   {"state-dir": true, "timeout": true, "install-path": true},
		"uninstall": {},
		"purge":     {"state-dir": true, "handle": true, "forget-metadata": true},
		"doctor":    {"state-dir": true, "pcrs": true, "collection": true},
	}

	for _, flagName := range []string{"state-dir", "pcrs", "collection", "timeout", "handle", "install-path", "forget-metadata"} {
		used := false
		fs.Visit(func(f *flag.Flag) {
			used = used || f.Name == flagName
		})
		if used && !allowed[cmd][flagName] {
			return fmt.Errorf("flag -%s is not valid for %s", flagName, cmd)
		}
	}

	return nil
}

func defaultConfig() (config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return config{}, err
	}

	exe, err := os.Executable()
	if err != nil {
		exe = appName
	}

	cfg := config{
		dir:         filepath.Join(home, ".local", "share", appName),
		pcrs:        "sha256:7",
		timeout:     retryTimeout,
		installPath: exe,
		systemdPath: filepath.Join(
			home,
			".config",
			"systemd",
			"user",
			serviceName,
		),
		handle: defaultSealedHandle,
	}

	cfg.refreshPaths()

	return cfg, nil
}

func (c *config) refreshPaths() {
	c.metadata = filepath.Join(c.dir, "metadata.json")
}

// ---------------------------------------------------------------------------
// Process hardening, signals and secret buffers
// ---------------------------------------------------------------------------

// hardenProcess makes the process non-dumpable (best effort). This blocks
// core dumps and, together with the kernel's ptrace rules, reading the
// secret out of the process memory by other same-UID processes.
func hardenProcess() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

var (
	interruptCh    = make(chan struct{})
	interruptCount int32
	handlerOnce    sync.Once
)

// installSignalHandler makes SIGINT/SIGTERM/SIGHUP non-fatal for commands
// that change TPM or local state. The first signal only sets a flag that the
// code checks at safe points, so a persistent TPM object is never orphaned by
// an interrupted enrollment. A second signal forces exit.
func installSignalHandler() {
	handlerOnce.Do(func() {
		ch := make(chan os.Signal, 4)

		signal.Notify(
			ch,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGHUP,
		)

		go func() {
			for sig := range ch {
				if atomic.AddInt32(&interruptCount, 1) == 1 {
					close(interruptCh)

					fmt.Fprintf(
						os.Stderr,
						"\n%s received: finishing the current step safely (send it again to force quit)\n",
						sig,
					)

					continue
				}

				fmt.Fprintln(
					os.Stderr,
					"\nforced exit; TPM state may need manual inspection: tpm2_getcap handles-persistent",
				)

				os.Exit(130)
			}
		}()
	})
}

func interrupted() bool {
	select {
	case <-interruptCh:
		return true
	default:
		return false
	}
}

func checkInterrupted() error {
	if interrupted() {
		return errInterrupted
	}

	return nil
}

func sleepInterruptible(d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-interruptCh:
		return errInterrupted
	}
}

// newSecretBuf returns a buffer whose capacity is rounded to a page multiple.
// The memory is locked (best effort) so it is not written to swap.
func newSecretBuf(size int) []byte {
	if size <= 0 {
		return nil
	}

	pageSize := os.Getpagesize()
	aligned := (size + pageSize - 1) &^ (pageSize - 1)
	b := make([]byte, aligned)

	_ = unix.Mlock(b)

	return b[:0]
}

// releaseSecretBuf zeroes the whole capacity of a buffer obtained from
// newSecretBuf (or a slice of it) and unlocks the memory.
func releaseSecretBuf(b []byte) {
	if cap(b) == 0 {
		return
	}

	full := b[:cap(b)]

	zero(full)

	_ = unix.Munlock(full)
}

func zero(
	b []byte,
) {
	for i := range b {
		b[i] = 0
	}
}

// ---------------------------------------------------------------------------
// Trusted external tools
// ---------------------------------------------------------------------------

// resolveTool finds an executable in trustedToolDirs. The file must be a
// root-owned regular file that is not writable by group or others, so a
// user-writable directory in PATH can never substitute a tpm2_* tool.
func resolveTool(name string) (string, error) {
	if p, ok := toolCache[name]; ok {
		return p, nil
	}

	for _, dir := range trustedToolDirs {
		p := filepath.Join(dir, name)

		info, err := os.Stat(p)
		if err != nil ||
			!info.Mode().IsRegular() ||
			info.Mode().Perm()&0111 == 0 {
			continue
		}

		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok ||
			st.Uid != 0 ||
			info.Mode().Perm()&0022 != 0 {
			continue
		}

		toolCache[name] = p

		return p, nil
	}

	return "", fmt.Errorf(
		"%s not found in trusted directories (%s); it must be a root-owned executable not writable by group or others",
		name,
		strings.Join(trustedToolDirs, ":"),
	)
}

// childEnv returns a minimal environment for external tools: PATH is replaced
// by the trusted directories and loader / TPM wiring variables are dropped so
// child commands consistently operate in a known environment.
func childEnv() []string {
	src := os.Environ()

	env := make([]string, 0, len(src)+1)

	for _, kv := range src {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "PATH":
			continue
		case strings.HasPrefix(name, "LD_"):
			continue
		case strings.HasPrefix(name, "TPM2TOOLS_"):
			continue
		case strings.HasPrefix(name, "TSS2_"):
			continue
		}

		env = append(env, kv)
	}

	return append(
		env,
		"PATH="+strings.Join(trustedToolDirs, ":"),
	)
}

func requireCommands(
	names ...string,
) error {
	var missing []string

	for _, name := range names {
		if _, err := resolveTool(name); err != nil {
			missing = append(
				missing,
				name,
			)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf(
			"missing commands (searched only root-owned files in %s): %s",
			strings.Join(trustedToolDirs, ":"),
			strings.Join(
				missing,
				", ",
			),
		)
	}

	return nil
}

// ---------------------------------------------------------------------------
// D-Bus helpers and error classification
// ---------------------------------------------------------------------------

type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func markTransient(err error) error {
	if err == nil {
		return nil
	}

	return &transientError{err: err}
}

func markPermanent(err error) error {
	if err == nil {
		return nil
	}

	return &permanentError{err: err}
}

func isTransient(err error) bool {
	var t *transientError

	return errors.As(err, &t)
}

func isPermanent(err error) bool {
	var p *permanentError

	return errors.As(err, &p)
}

// D-Bus errors that mean "the service or object is not there (yet)".
var transientDBusErrors = map[string]struct{}{
	"org.freedesktop.DBus.Error.ServiceUnknown": {},
	"org.freedesktop.DBus.Error.NameHasNoOwner": {},
	"org.freedesktop.DBus.Error.NoReply":        {},
	"org.freedesktop.DBus.Error.Timeout":        {},
	"org.freedesktop.DBus.Error.TimedOut":       {},
	"org.freedesktop.DBus.Error.Disconnected":   {},
	"org.freedesktop.DBus.Error.UnknownObject":  {},
	"org.freedesktop.Secret.Error.NoSuchObject": {},
}

// dbusErrorName extracts the D-Bus error name from an error chain.
func dbusErrorName(err error) string {
	for e := err; e != nil; e = errors.Unwrap(e) {
		switch de := e.(type) {
		case dbus.Error:
			return de.Name
		case *dbus.Error:
			if de != nil {
				return de.Name
			}
		}
	}

	return ""
}

func classifyDBusError(err error) error {
	if err == nil {
		return nil
	}

	if _, ok := transientDBusErrors[dbusErrorName(err)]; ok {
		return markTransient(err)
	}

	return err
}

// dbusConn opens a private session bus connection. Failure to connect is
// treated as transient because the bus may not be up yet during login.
func dbusConn() (*dbus.Conn, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, markTransient(err)
	}

	return conn, nil
}

func readDefaultCollection() (string, error) {
	conn, err := dbusConn()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	obj := conn.Object(
		secretServiceName,
		dbus.ObjectPath(secretServicePath),
	)

	var collection dbus.ObjectPath

	if err := obj.Call(
		"org.freedesktop.Secret.Service.ReadAlias",
		0,
		"default",
	).Store(&collection); err != nil {
		return "",
			fmt.Errorf(
				"ReadAlias default failed: %w",
				classifyDBusError(err),
			)
	}

	if err := validateDBusObjectPath(string(collection)); err != nil {
		if collection == "/" {
			err = markTransient(err)
		}

		return "",
			fmt.Errorf(
				"ReadAlias default returned invalid collection path %q: %w",
				collection,
				err,
			)
	}

	return string(collection), nil
}

// resolveCollection selects the collection to use for an operation. An
// explicitly supplied path wins. A recorded path is used only while it still
// resolves to a live Secret Service collection; otherwise the current default
// alias is queried.
func resolveCollection(
	explicit,
	recorded string,
	timeout time.Duration,
) (string, error) {
	return resolveCollectionWithRetry(
		explicit,
		recorded,
		timeout,
		collectionLocked,
		readDefaultCollection,
	)
}

func resolveCollectionWithRetry(
	explicit,
	recorded string,
	timeout time.Duration,
	collectionLockedFn func(string) (bool, error),
	readDefaultFn func() (string, error),
) (string, error) {
	if explicit != "" {
		if err := validateDBusObjectPath(explicit); err != nil {
			return "", err
		}

		return explicit, nil
	}

	if recorded != "" {
		if err := validateDBusObjectPath(recorded); err != nil {
			return "", fmt.Errorf(
				"recorded collection object path: %w",
				err,
			)
		}
	}

	var selected string

	err := withRetry(
		timeout,
		func() error {
			if recorded != "" {
				if _, err := collectionLockedFn(recorded); err == nil {
					selected = recorded
					return nil
				} else {
					err = classifyDBusError(err)
					if !isMissingCollectionError(err) {
						if isTransient(err) {
							return err
						}

						return fmt.Errorf(
							"recorded collection %s is unavailable: %w",
							recorded,
							err,
						)
					}
				}
			}

			collection, err := readDefaultFn()
			if err != nil {
				return err
			}

			if _, err := collectionLockedFn(collection); err == nil {
				selected = collection
				return nil
			} else {
				err = classifyDBusError(err)
				if !isMissingCollectionError(err) && !isTransient(err) {
					return fmt.Errorf(
						"default collection %s is unavailable: %w",
						collection,
						err,
					)
				}
				return err
			}
		},
	)
	if err != nil {
		return "", err
	}

	if selected != "" {
		return selected, nil
	}

	return "", errors.New("no Secret Service collection available")
}

func isMissingCollectionError(err error) bool {
	switch dbusErrorName(err) {
	case "org.freedesktop.DBus.Error.UnknownObject",
		"org.freedesktop.Secret.Error.NoSuchObject":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// enroll
// ---------------------------------------------------------------------------

func enroll(cfg config) error {
	if err := requireCommands(
		"tpm2_getcap",
		"tpm2_createprimary",
		"tpm2_create",
		"tpm2_load",
		"tpm2_startauthsession",
		"tpm2_policypcr",
		"tpm2_flushcontext",
		"tpm2_evictcontrol",
		"tpm2_readpublic",
		"tpm2_unseal",
	); err != nil {
		return err
	}

	if err := validatePersistentHandle(cfg.handle); err != nil {
		return fmt.Errorf(
			"invalid -handle %q: %w",
			cfg.handle,
			err,
		)
	}

	if err := validatePCRSelection(cfg.pcrs); err != nil {
		return fmt.Errorf(
			"invalid PCR selection %q: %w",
			cfg.pcrs,
			err,
		)
	}

	if err := validateDBusObjectPath(cfg.collection); err != nil {
		return fmt.Errorf(
			"invalid collection object path %q: %w",
			cfg.collection,
			err,
		)
	}

	if err := checkTPMReady(); err != nil {
		return err
	}

	if err := checkExistingStatePermissions(cfg); err != nil {
		return fmt.Errorf("state permissions: %w", err)
	}

	/*
		Enrollment replacement is deliberately explicit.

		We do NOT automatically evict an existing persistent object.
		That avoids a non-atomic "remove old -> install new" window.

		To replace an enrollment:
		    tpm-keyring-unlock purge
		    tpm-keyring-unlock enroll
	*/
	if _, statErr := os.Lstat(cfg.metadata); statErr == nil {
		md, readErr := readMetadata(cfg)

		switch {
		case readErr != nil:
			return fmt.Errorf(
				"metadata file %s already exists but is unreadable or invalid (%v); "+
					"if the enrollment is not needed run '%s purge -forget-metadata' "+
					"and then check for an orphaned TPM object with 'tpm2_getcap handles-persistent'",
				cfg.metadata,
				readErr,
				appName,
			)

		case md.App != appName:
			return fmt.Errorf(
				"metadata file %s belongs to a different application (%q); refusing to touch it",
				cfg.metadata,
				md.App,
			)

		default:
			return fmt.Errorf(
				"an enrollment already exists; run '%s purge' before re-enrolling",
				appName,
			)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}

	if available, err := persistentSlotsAvailable(); err == nil && available == 0 {
		return errors.New("TPM has no persistent handle slots available")
	}

	// Validate the state directory BEFORE any TPM state is changed.
	if err := ensureStateDir(cfg); err != nil {
		return err
	}

	if !cfg.handleExplicit {
		handles, err := persistentHandles()
		if err != nil {
			return fmt.Errorf(
				"inspect persistent handles: %w",
				err,
			)
		}

		defaultValue, _ := strconv.ParseUint(defaultSealedHandle[2:], 16, 32)
		if _, exists := handles[defaultValue]; exists {
			cfg.handle, err = allocatePersistentHandle(handles)
			if err != nil {
				return err
			}

			fmt.Printf(
				"default persistent handle %s is occupied; using %s; the existing object's identity is unknown, inspect it with 'tpm2_readpublic -c %s'\n",
				defaultSealedHandle,
				cfg.handle,
				defaultSealedHandle,
			)
		}
	}

	state, err := inspectPersistent(
		cfg.handle,
		"",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect target persistent handle %s: %w",
			cfg.handle,
			err,
		)
	}

	if state != handleAbsent {
		return fmt.Errorf(
			"persistent handle %s is already occupied (%s); "+
				"refusing to modify it; use another -handle or purge the existing enrollment",
			cfg.handle,
			state,
		)
	}

	fmt.Print("GNOME keyring master password: ")

	secret, err := readPassword()
	if err != nil {
		return err
	}
	defer releaseSecretBuf(secret)

	if len(secret) == 0 {
		return errors.New(
			"empty keyring password refused",
		)
	}

	if len(secret) > maxSealedSecretSize {
		return fmt.Errorf(
			"keyring password is %d bytes; TPM sealed data is limited to %d bytes",
			len(secret),
			maxSealedSecretSize,
		)
	}

	if err := checkInterrupted(); err != nil {
		return err
	}

	fmt.Println(colorize(
		"verifying password against the real default collection...",
		colorDim,
	))

	if err := verifyKeyringPassword(
		cfg.collection,
		secret,
	); err != nil {
		return err
	}

	if err := checkInterrupted(); err != nil {
		return err
	}

	tmp, err := os.MkdirTemp("", appName+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	primaryCtx := filepath.Join(
		tmp,
		"primary.ctx",
	)

	sealedPub := filepath.Join(
		tmp,
		"keyring.pub",
	)

	sealedPriv := filepath.Join(
		tmp,
		"keyring.priv",
	)

	keyCtx := filepath.Join(
		tmp,
		"key.ctx",
	)

	if err := runCmd(
		nil,
		"tpm2_createprimary",
		"-C", "o",
		"-G", "ecc",
		"-c", primaryCtx,
	); err != nil {
		return err
	}

	policyDigest := filepath.Join(
		tmp,
		"policy.digest",
	)

	sessionCtx := filepath.Join(
		tmp,
		"trial.ctx",
	)

	if err := runCmd(
		nil,
		"tpm2_startauthsession",
		"-S", sessionCtx,
		"-g", "sha256",
	); err != nil {
		return err
	}

	if err := runCmd(
		nil,
		"tpm2_policypcr",
		"-S", sessionCtx,
		"-l", cfg.pcrs,
		"-L", policyDigest,
	); err != nil {
		_ = runCmd(
			nil,
			"tpm2_flushcontext",
			sessionCtx,
		)

		return err
	}

	if err := runCmd(
		nil,
		"tpm2_flushcontext",
		sessionCtx,
	); err != nil {
		return err
	}

	if err := runCmd(
		bytes.NewReader(secret),
		"tpm2_create",
		"-C", primaryCtx,
		"-u", sealedPub,
		"-r", sealedPriv,
		"-i", "-",
		"-L", policyDigest,
		"-a", "fixedtpm|fixedparent|adminwithpolicy",
	); err != nil {
		return err
	}

	if err := os.Chmod(sealedPub, 0600); err != nil {
		return err
	}

	if err := os.Chmod(sealedPriv, 0600); err != nil {
		return err
	}

	if err := runCmd(
		nil,
		"tpm2_load",
		"-C", primaryCtx,
		"-u", sealedPub,
		"-r", sealedPriv,
		"-c", keyCtx,
	); err != nil {
		return err
	}

	// The Name of the freshly loaded object is what must later be found at
	// the persistent handle; it is used to verify the persist step and to
	// safely roll it back.
	expectedName, err := objectName(keyCtx)
	if err != nil {
		return fmt.Errorf(
			"read Name of the new sealed object: %w",
			err,
		)
	}

	fmt.Println(colorize(
		"self-testing newly created sealed secret...",
		colorDim,
	))

	selfTestSecret, err := unsealLoaded(
		keyCtx,
		cfg.pcrs,
	)
	if err != nil {
		return fmt.Errorf(
			"enroll self-test failed: %w",
			err,
		)
	}
	defer releaseSecretBuf(selfTestSecret)

	if !bytes.Equal(
		selfTestSecret,
		secret,
	) {
		return errors.New(
			"enroll self-test failed: unsealed secret mismatch",
		)
	}

	// Last safe point to abort. From here on the TPM state is changed and the
	// remaining steps run to completion (or roll back) even if a signal
	// arrives.
	if err := checkInterrupted(); err != nil {
		return err
	}

	if err := persistSealed(
		cfg,
		keyCtx,
		expectedName,
		secret,
	); err != nil {
		return fmt.Errorf(
			"persistent enrollment failed: %w",
			err,
		)
	}

	if err := writeMetadata(
		cfg,
		cfg.handle,
		expectedName,
	); err != nil {
		if removeErr := removePersistent(
			cfg.handle,
			expectedName,
		); removeErr != nil {
			return fmt.Errorf(
				"metadata write failed: %w; additionally could not remove "+
					"new persistent object %s: %v",
				err,
				cfg.handle,
				removeErr,
			)
		}

		return fmt.Errorf(
			"metadata write failed; persistent object rolled back: %w",
			err,
		)
	}

	fmt.Println(colorize(
		"persistent sealed object enabled at",
		colorGreen,
	), cfg.handle)

	fmt.Println(colorize(
		"enrolled sealed secret in TPM",
		colorGreen,
	))

	fmt.Println(colorize(
		"note: the policy has no PIN/authValue; any process able to use /dev/tpmrm0 "+
			"while the PCRs match can unseal the secret (see '"+appName+" doctor')",
		colorDim,
	))

	return nil
}

// verifyKeyringPassword proves that secret really is the master password of
// the collection.
//
// UnlockWithMasterPassword on an ALREADY UNLOCKED collection succeeds without
// validating the password (observed in testing: enrolling a wrong password
// on an unlocked keyring did not fail). So an unlocked collection is locked
// first, and the password is then verified by really unlocking it. Success
// requires the collection to end up unlocked.
//
// If the password is wrong, the collection is left locked; re-running enroll
// with the correct password unlocks it again.
func verifyKeyringPassword(
	collection string,
	secret []byte,
) error {
	locked, err := collectionLocked(collection)
	if err != nil {
		return fmt.Errorf(
			"read collection state: %w",
			err,
		)
	}

	if !locked {
		fmt.Println(colorize(
			"collection is unlocked; locking it temporarily so the password can be verified for real...",
			colorDim,
		))

		if err := lockCollection(collection); err != nil {
			return fmt.Errorf(
				"lock collection for verification: %w",
				err,
			)
		}

		locked, err = collectionLocked(collection)
		if err != nil {
			return fmt.Errorf(
				"read collection state after lock: %w",
				err,
			)
		}

		if !locked {
			return errors.New(
				"could not lock the collection (a prompt may be required); " +
					"refusing to enroll an unverified password; " +
					"lock the collection manually (for example with seahorse) and re-run enroll",
			)
		}
	}

	if err := unlockCollection(collection, secret); err != nil {
		return fmt.Errorf(
			"password did not unlock the collection (the collection stays locked; "+
				"re-run enroll with the correct password): %w",
			err,
		)
	}

	locked, err = collectionLocked(collection)
	if err != nil {
		return fmt.Errorf(
			"read collection state after unlock: %w",
			err,
		)
	}

	if locked {
		return errors.New(
			"unlock reported success but the collection is still locked; password not verified",
		)
	}

	return nil
}

// persistSealed makes the loaded object persistent and verifies it.
//
// Any failure after tpm2_evictcontrol was started (including a failure of
// evictcontrol itself, which may have executed inside the TPM before the tool
// was interrupted or failed) is rolled back by Name, so an orphaned
// persistent object cannot remain.
func persistSealed(
	cfg config,
	keyCtx string,
	expectedName string,
	secret []byte,
) error {
	if err := validatePersistentHandle(cfg.handle); err != nil {
		return err
	}

	exists, err := persistentHandleExists(
		cfg.handle,
	)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf(
			"persistent handle %s became occupied unexpectedly",
			cfg.handle,
		)
	}

	rollback := func(cause error) error {
		if removeErr := removePersistent(
			cfg.handle,
			expectedName,
		); removeErr != nil {
			return fmt.Errorf(
				"%w; additionally could not remove %s: %v "+
					"(inspect it manually: tpm2_getcap handles-persistent)",
				cause,
				cfg.handle,
				removeErr,
			)
		}

		return cause
	}

	if err := runCmd(
		nil,
		"tpm2_evictcontrol",
		"-C", "o",
		"-c", keyCtx,
		cfg.handle,
	); err != nil {
		return rollback(err)
	}

	gotName, err := persistentObjectName(
		cfg.handle,
	)
	if err != nil {
		return rollback(fmt.Errorf(
			"read Name of persistent object: %w",
			err,
		))
	}

	if !strings.EqualFold(
		gotName,
		expectedName,
	) {
		return rollback(fmt.Errorf(
			"Name of the persistent object (%s) does not match the object created by this run (%s)",
			gotName,
			expectedName,
		))
	}

	fmt.Println(colorize(
		"self-testing persistent sealed object...",
		colorDim,
	))

	got, err := unsealPersistent(
		cfg.handle,
		cfg.pcrs,
	)

	if err == nil &&
		!bytes.Equal(got, secret) {
		err = errors.New(
			"unsealed secret mismatch",
		)
	}

	releaseSecretBuf(got)

	if err != nil {
		return rollback(fmt.Errorf(
			"persistent self-test failed: %w",
			err,
		))
	}

	return nil
}

// ---------------------------------------------------------------------------
// unlock / status / install / uninstall / purge / doctor
// ---------------------------------------------------------------------------

func unlock(cfg config) error {
	// Security boundary: validate the state directory and metadata path
	// BEFORE reading any durable state through cfg.dir.
	if err := checkExistingStatePermissions(cfg); err != nil {
		return fmt.Errorf(
			"state permissions: %w",
			err,
		)
	}

	md, err := enrollmentMetadata(cfg)
	if err != nil {
		return fmt.Errorf(
			"read enrollment metadata: %w",
			err,
		)
	}

	cfg.collection, err = resolveCollection(
		cfg.collection,
		md.Collection,
		cfg.timeout,
	)
	if err != nil {
		return fmt.Errorf(
			"resolve Secret Service collection: %w",
			err,
		)
	}

	cfg.pcrs = md.PCRs
	cfg.handle = md.Handle

	// The state permissions were already checked before metadata was read.
	// Keep the rest of unlock focused on the actual enrollment.
	locked, err := collectionLockedWithRetry(
		cfg.collection,
		cfg.timeout,
	)
	if err != nil {
		return err
	}

	if !locked {
		fmt.Println(colorize(
			"collection already unlocked",
			colorGreen,
		))
		return nil
	}

	secret, err := unsealSecret(
		cfg,
		md,
	)
	if err != nil {
		return err
	}
	defer releaseSecretBuf(secret)

	if err := unlockCollectionWithRetry(
		cfg.collection,
		secret,
		cfg.timeout,
	); err != nil {
		return err
	}

	locked, err = collectionLockedWithRetry(
		cfg.collection,
		cfg.timeout,
	)
	if err != nil {
		return err
	}

	if locked {
		return errors.New(
			"unlock method returned success but collection remains locked",
		)
	}

	fmt.Println(colorize(
		"collection unlocked",
		colorGreen,
	))

	return nil
}

// statusCollectionState resolves the enrolled collection and reads its Locked
// property with a hard upper bound. withRetry only checks its deadline between
// attempts, so a single blocked D-Bus call could otherwise exceed the timeout.
// The goroutine may outlive the timeout, which is harmless because status
// returns right after and the process exits.
func statusCollectionState(
	recorded string,
	timeout time.Duration,
) (bool, error) {
	limit := timeout
	if limit <= 0 {
		limit = statusTimeout
	}

	type result struct {
		locked bool
		err    error
	}

	done := make(chan result, 1)

	go func() {
		collection, err := resolveCollection("", recorded, timeout)
		if err != nil {
			done <- result{err: err}
			return
		}

		locked, err := collectionLocked(collection)
		done <- result{locked: locked, err: err}
	}()

	select {
	case r := <-done:
		return r.locked, r.err

	case <-time.After(limit + retryInterval):
		return false, fmt.Errorf("timed out after %s", limit)
	}
}

func status(cfg config) error {
	fmt.Println("state dir:", cfg.dir)

	statePermissionsErr := checkExistingStatePermissions(cfg)
	if statePermissionsErr != nil {
		fmt.Println("enrolled: false")
		fmt.Println("metadata: unavailable: state permissions:", statePermissionsErr)
		printCheck("state permissions", statePermissionsErr)

		_, statErr := os.Stat(cfg.systemdPath)
		fmt.Println("systemd user service installed:", statErr == nil)

		return statePermissionsErr
	}

	var statusErr error

	md, err := enrollmentMetadata(cfg)
	if err != nil {
		fmt.Println("enrolled: false")
		fmt.Println("metadata: unavailable:", err)

		printCheck("state permissions", statePermissionsErr)

		_, statErr := os.Stat(cfg.systemdPath)
		fmt.Println("systemd user service installed:", statErr == nil)

		if !errors.Is(err, os.ErrNotExist) {
			statusErr = err
		}

		return statusErr
	}

	fmt.Println("enrolled: true")
	fmt.Println("enrolled collection:", md.Collection)
	fmt.Println("enrolled PCRs:", md.PCRs)
	fmt.Println("metadata version:", md.Version)
	fmt.Println("metadata created:", md.CreatedAt.Format(time.RFC3339))
	fmt.Println("persistent sealed object:", md.Handle)

	state, inspectErr := inspectPersistent(md.Handle, md.HandleName)
	if inspectErr != nil {
		fmt.Printf("persistent object state: unknown: %v\n", inspectErr)
		statusErr = errors.New("persistent object could not be verified")
	} else {
		fmt.Println("persistent object state:", state)

		if state != handleOurs {
			statusErr = fmt.Errorf("persistent object state is %s", state)
		}
	}

	if state == handleOurs {
		if currentName, nameErr := persistentObjectName(md.Handle); nameErr == nil {
			fmt.Println("persistent object Name:", currentName)
		}
	}

	printCheck("state permissions", statePermissionsErr)

	locked, lockedErr := statusCollectionState(md.Collection, cfg.timeout)
	if lockedErr != nil {
		fmt.Println("collection locked: unknown:", lockedErr)
	} else {
		fmt.Println("collection locked:", locked)
	}

	_, err = os.Stat(cfg.systemdPath)
	fmt.Println("systemd user service installed:", err == nil)

	return statusErr
}

func install(cfg config) error {
	if err := validateInstallPath(cfg.installPath); err != nil {
		return err
	}

	if err := rejectSymlinkComponents(filepath.Dir(cfg.systemdPath)); err != nil {
		return fmt.Errorf("systemd unit directory: %w", err)
	}

	if err := os.MkdirAll(
		filepath.Dir(cfg.systemdPath),
		0755,
	); err != nil {
		return err
	}

	if info, err := os.Lstat(cfg.systemdPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("systemd unit path %s must not be a symlink", cfg.systemdPath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	quoted := make([]string, 0, 6)

	for _, arg := range []string{
		filepath.Clean(cfg.installPath),
		"unlock",
		"--state-dir",
		cfg.dir,
		"--timeout",
		cfg.timeout.String(),
	} {
		q, err := quoteSystemdArg(arg)
		if err != nil {
			return err
		}

		quoted = append(quoted, q)
	}

	args := strings.Join(
		quoted,
		" ",
	)

	unit := fmt.Sprintf(`[Unit]
Description=Unlock GNOME keyring default collection using TPM2 sealed secret

[Service]
Type=oneshot
NoNewPrivileges=yes
ExecStart=%s

[Install]
WantedBy=default.target
`, args)

	tmpFile, err := os.CreateTemp(filepath.Dir(cfg.systemdPath), "."+serviceName+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	cleanup := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}

	if err := tmpFile.Chmod(0644); err != nil {
		cleanup()
		return err
	}
	if _, err := tmpFile.Write([]byte(unit)); err != nil {
		cleanup()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, cfg.systemdPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := syncDir(filepath.Dir(cfg.systemdPath)); err != nil {
		return err
	}

	if err := runCmd(
		nil,
		"systemctl",
		"--user",
		"daemon-reload",
	); err != nil {
		return err
	}

	if err := runCmd(
		nil,
		"systemctl",
		"--user",
		"enable",
		serviceName,
	); err != nil {
		return err
	}

	fmt.Println(
		colorize("installed", colorGreen),
		cfg.systemdPath,
	)

	return nil
}

// validateInstallPath refuses paths that would leave the unit pointing at a
// binary that is about to disappear (typically 'go run' output in a temporary
// directory) or at something that is not an executable file.
func validateInstallPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf(
			"install path %q is not absolute; pass -install-path /absolute/path/to/%s",
			path,
			appName,
		)
	}

	clean := filepath.Clean(path)

	if err := rejectSymlinkComponents(clean); err != nil {
		return fmt.Errorf("install path: %w", err)
	}

	insideTemp := false

	tmpDir := filepath.Clean(os.TempDir())

	if rel, err := filepath.Rel(tmpDir, clean); err == nil &&
		rel != ".." &&
		!strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		insideTemp = true
	}

	// This check must run before the parent directory check: /tmp is
	// world-writable, and the temporary-build hint is far more useful than a
	// generic permission error.
	if insideTemp || strings.Contains(clean, "go-build") {
		return fmt.Errorf(
			"install path %q looks like a temporary build (for example 'go run'); "+
				"build the binary with 'go build', install it somewhere permanent and run that, "+
				"or pass -install-path",
			clean,
		)
	}

	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf(
			"install path: %w",
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf(
			"install path %q is not an executable regular file",
			clean,
		)
	}

	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf(
			"install path %q is writable by group or others",
			clean,
		)
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := uint64(stat.Uid)
		if uid != 0 && uid != uint64(os.Getuid()) {
			return fmt.Errorf(
				"install path %q is owned by UID %d, want root or UID %d",
				clean,
				uid,
				os.Getuid(),
			)
		}
	}

	return validateInstallPathParents(clean)
}

// validateInstallDir checks a single directory on the path to the installed
// binary: it must be a real directory (not a symlink), owned by root or the
// current user, and not writable by group or others.
func validateInstallDir(dir string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("install path directory %q must not be a symlink", dir)
	}

	if !info.IsDir() {
		return fmt.Errorf("install path directory %q is not a directory", dir)
	}

	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf(
			"install path directory %q is writable by group or others (mode %04o); "+
				"tighten it (for example: chmod go-w %s) or install the binary in a directory "+
				"that only you and root can modify",
			dir,
			info.Mode().Perm(),
			shellQuote(dir),
		)
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := uint64(stat.Uid)
		if uid != 0 && uid != uint64(os.Getuid()) {
			return fmt.Errorf(
				"install path directory %q is owned by UID %d, want root or UID %d",
				dir,
				uid,
				os.Getuid(),
			)
		}
	}

	return nil
}

// validateInstallPathParents verifies that every directory on the path to the
// installed binary passes validateInstallDir, so another local user cannot
// replace the binary through directory permissions after the unit has been
// installed. The check runs only at install time.
func validateInstallPathParents(path string) error {
	current := string(filepath.Separator)

	for _, component := range strings.Split(
		strings.TrimPrefix(filepath.Dir(path), current),
		string(filepath.Separator),
	) {
		if component == "" {
			continue
		}

		current = filepath.Join(current, component)

		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("install path directory %q: %w", current, err)
		}

		if err := validateInstallDir(current, info); err != nil {
			return err
		}
	}

	return nil
}

func uninstall(cfg config) error {
	if _, err := os.Stat(
		cfg.systemdPath,
	); err == nil {
		if err := runCmd(
			nil,
			"systemctl",
			"--user",
			"stop",
			serviceName,
		); err != nil {
			return err
		}

		if err := runCmd(
			nil,
			"systemctl",
			"--user",
			"disable",
			serviceName,
		); err != nil {
			return err
		}
	} else if !errors.Is(
		err,
		os.ErrNotExist,
	) {
		return err
	}

	if err := os.Remove(
		cfg.systemdPath,
	); err != nil &&
		!errors.Is(
			err,
			os.ErrNotExist,
		) {
		return err
	}

	if err := runCmd(
		nil,
		"systemctl",
		"--user",
		"daemon-reload",
	); err != nil {
		return err
	}

	fmt.Println(
		colorize("uninstalled", colorGreen),
		cfg.systemdPath,
	)

	return nil
}

func forgetHint() string {
	return fmt.Sprintf(
		"if the TPM object is not needed (or is already gone) run '%s purge -forget-metadata' "+
			"to delete only the local state files",
		appName,
	)
}

func purge(cfg config) error {
	// Security boundary: never read or remove anything through a symlinked
	// state directory or metadata file.
	
	if err := checkExistingStatePermissions(cfg); err != nil {
		return fmt.Errorf(
			"state permissions: %w",
			err,
		)
	}

	if cfg.handleExplicit {
		if err := validatePersistentHandle(cfg.handle); err != nil {
			return fmt.Errorf(
				"invalid -handle %q: %w",
				cfg.handle,
				err,
			)
		}
	}

	if cfg.forgetMetadata {
		if cfg.handleExplicit {
			if md, err := readMetadata(cfg); err == nil &&
				!strings.EqualFold(md.Handle, cfg.handle) {
				return fmt.Errorf(
					"-handle %s does not match the enrolled handle %s; -handle is only for checking occupancy when metadata is absent",
					cfg.handle,
					md.Handle,
				)
			}
		}

		return forgetLocalState(cfg)
	}

	md, err := readMetadata(
		cfg,
	)

	switch {
	case err == nil:
		if md.App != appName {
			return fmt.Errorf(
				"metadata app mismatch: got %q, want %q; %s",
				md.App,
				appName,
				forgetHint(),
			)
		}

		if cfg.handleExplicit && !strings.EqualFold(cfg.handle, md.Handle) {
			return fmt.Errorf(
				"-handle %s does not match the enrolled handle %s; -handle is only for checking occupancy when metadata is absent",
				cfg.handle,
				md.Handle,
			)
		}

		// For purge we deliberately do not require the complete metadata
		// to be valid. Only the information required to safely identify
		// and remove our TPM object must remain trustworthy.
		if err := validatePersistentHandle(md.Handle); err != nil {
			return fmt.Errorf(
				"metadata has invalid persistent handle %q: %w; %s",
				md.Handle,
				err,
				forgetHint(),
			)
		}

		if err := validateTPMName(md.HandleName); err != nil {
			return fmt.Errorf(
				"metadata has invalid persistent TPM Name: %w; %s",
				err,
				forgetHint(),
			)
		}

		state, inspectErr := inspectPersistent(
			md.Handle,
			md.HandleName,
		)
		if inspectErr != nil {
			return fmt.Errorf(
				"cannot safely inspect persistent object %s: %w",
				md.Handle,
				inspectErr,
			)
		}

		switch state {
		case handleAbsent:
			// Nothing to remove.

		case handleOurs:
			if err := removePersistent(
				md.Handle,
				md.HandleName,
			); err != nil {
				return fmt.Errorf(
					"remove persistent sealed object %s: %w",
					md.Handle,
					err,
				)
			}

		case handleForeign:
			return fmt.Errorf(
				"persistent handle %s contains a different TPM object; refusing to purge it; %s",
				md.Handle,
				forgetHint(),
			)

		case handleUnverified:
			return fmt.Errorf(
				"persistent handle %s cannot be verified; refusing to purge it; %s",
				md.Handle,
				forgetHint(),
			)

		default:
			return fmt.Errorf(
				"unknown persistent handle state for %s",
				md.Handle,
			)
		}

	case errors.Is(err, os.ErrNotExist):
		// No metadata: nothing of ours is recorded. An occupied handle may be
		// an orphan from an interrupted enrollment, but its identity cannot be
		// verified, so it is only reported.
		warnIfHandleOccupied(
			cfg,
			"no enrollment metadata was found",
		)

	default:
		return fmt.Errorf(
			"cannot safely purge because metadata is unreadable: %w; %s",
			err,
			forgetHint(),
		)
	}

	removed, removeErr := removeEnrollment(cfg)
	if removeErr != nil {
		return removeErr
	}

	if removed == 0 {
		fmt.Println(
			colorize("no local enrollment state found in", colorDim),
			cfg.dir,
			"(TPM untouched)",
		)

		return nil
	}

	fmt.Println(
		colorize("purged sealed state from", colorYellow),
		cfg.dir,
	)

	return nil
}

// forgetLocalState deletes the local state files without touching the TPM.
func forgetLocalState(cfg config) error {
	// purge() normally performs this check first, but keep the security
	// invariant local to this destructive helper as well. This prevents a
	// future caller from accidentally turning forgetLocalState into a
	// symlink-following deletion primitive.
	if err := checkExistingStatePermissions(cfg); err != nil {
		return fmt.Errorf(
			"state permissions: %w",
			err,
		)
	}

	if md, err := readMetadata(cfg); err == nil &&
		validatePersistentHandle(md.Handle) == nil {
		if exists, existsErr := persistentHandleExists(
			md.Handle,
		); existsErr == nil && exists {
			fmt.Fprintf(
				os.Stderr,
				"%s persistent handle %s is still occupied and was NOT touched; "+
					"if it is yours, remove it manually: tpm2_evictcontrol -C o -c %s\n",
				colorizeStderr("warning:", colorYellow),
				md.Handle,
				md.Handle,
			)
		}
	}

	removed, err := removeEnrollment(cfg)
	if err != nil {
		return err
	}

	if removed == 0 {
		fmt.Println(
			colorize("no local state files found in", colorDim),
			cfg.dir,
			"(TPM untouched)",
		)

		return nil
	}

	fmt.Println(
		colorize("removed local state files (TPM untouched) from", colorYellow),
		cfg.dir,
	)

	return nil
}

func warnIfHandleOccupied(
	cfg config,
	reason string,
) {
	handles, err := persistentHandles()
	if err != nil {
		return
	}

	var candidates []uint64

	if cfg.handleExplicit {
		if validateErr := validatePersistentHandle(cfg.handle); validateErr != nil {
			return
		}

		value, parseErr := strconv.ParseUint(cfg.handle[2:], 16, 32)
		if parseErr != nil {
			return
		}

		candidates = append(candidates, value)
	} else {
		defaultValue, _ := strconv.ParseUint(defaultSealedHandle[2:], 16, 32)

		candidates = append(candidates, defaultValue)

		for value := dynamicHandleFirst; value <= dynamicHandleLast; value++ {
			candidates = append(candidates, value)
		}
	}

	seen := make(map[uint64]struct{}, len(candidates))

	for _, value := range candidates {
		if _, alreadyReported := seen[value]; alreadyReported {
			continue
		}
		seen[value] = struct{}{}

		if _, occupied := handles[value]; !occupied {
			continue
		}

		handle := fmt.Sprintf("0x%08x", value)

		fmt.Fprintf(
			os.Stderr,
			"%s %s, but persistent handle %s is occupied. Its identity cannot be verified, "+
				"so it was NOT touched. If it is an orphan from an interrupted enrollment, inspect it with "+
				"'tpm2_readpublic -c %s' and remove it with 'tpm2_evictcontrol -C o -c %s'.\n",
			colorizeStderr("warning:", colorYellow),
			reason,
			handle,
			handle,
			handle,
		)
	}
}

// removeEnrollment deletes the local enrollment files and returns how many
// files were actually removed. Files that do not exist are not an error.
func removeEnrollment(cfg config) (int, error) {
	removed := 0

	remove := func(path string) error {
		err := os.Remove(path)
		if err == nil {
			removed++
			return nil
		}

		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	for _, path := range []string{
		cfg.metadata,
		filepath.Join(cfg.dir, "keyring.pub"),
		filepath.Join(cfg.dir, "keyring.priv"),
		filepath.Join(cfg.dir, "secret.sha256"),
	} {
		if err := remove(path); err != nil {
			return removed, err
		}
	}

	entries, err := os.ReadDir(cfg.dir)
	if errors.Is(err, os.ErrNotExist) {
		return removed, nil
	}
	if err != nil {
		return removed, err
	}

	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".metadata.json.tmp-") {
			continue
		}

		if err := remove(filepath.Join(cfg.dir, entry.Name())); err != nil {
			return removed, err
		}
	}

	return removed, nil
}

func doctor(cfg config) error {
	if !cfg.pcrsExplicit {
		if md, err := readMetadata(cfg); err == nil && md.PCRs != "" {
			cfg.pcrs = md.PCRs
		}
	}

	var failed bool

	fmt.Println(
		colorize("Tooling", colorBold),
	)

	for _, c := range []string{
		"tpm2_getcap",
		"tpm2_pcrread",
		"tpm2_createprimary",
		"tpm2_create",
		"tpm2_load",
		"tpm2_unseal",
		"tpm2_startauthsession",
		"tpm2_policypcr",
		"tpm2_flushcontext",
		"tpm2_evictcontrol",
		"tpm2_readpublic",
		"systemctl",
	} {
		_, err := resolveTool(c)
		ok := err == nil
		printBool(
			c,
			ok,
		)
		if !ok {
			failed = true
		}
	}

	fmt.Println()
	fmt.Println(
		colorize("TPM", colorBold),
	)

	if line, err := tpmDeviceSummary(); err == nil {
		fmt.Println(line)
	} else {
		fmt.Println(
			"/dev/tpmrm0          " +
				colorize("missing", colorRed) +
				": " +
				err.Error(),
		)
	}

	var idOut bytes.Buffer

	if err := runCmdOut(
		&idOut,
		nil,
		"id",
	); err == nil {
		fmt.Print(
			strings.TrimSpace(
				idOut.String(),
			),
			"\n",
		)
	}

	if err := runDiagnosticCmd(
		"tpm2_getcap",
		"properties-fixed",
	); err != nil {
		printCheck("tpm properties", err)
		failed = true
	} else {
		printCheck("tpm properties", nil)
	}

	if available, err := persistentSlotsAvailable(); err != nil {
		printCheck("persistent TPM slots", err)
		failed = true
	} else if available == 0 {
		printCheck(
			"persistent TPM slots",
			errors.New("TPM has no persistent handle slots available"),
		)
		failed = true
	} else {
		fmt.Printf(
			"%-28s %s: %d available\n",
			"persistent TPM slots",
			colorize("ok", colorGreen),
			available,
		)
	}

	if err := validatePCRSelection(cfg.pcrs); err != nil {
		printCheck(
			"tpm pcr selection",
			err,
		)
		failed = true
	} else {
		if err := runDiagnosticCmd(
			"tpm2_pcrread",
			cfg.pcrs,
		); err != nil {
			printCheck("tpm "+cfg.pcrs, err)
			failed = true
		} else {
			printCheck("tpm "+cfg.pcrs, nil)
		}
	}

	printTPMPermissionAdvice()

	fmt.Println()
	fmt.Println(
		colorize("DBus", colorBold),
	)

	sessionBusErr := checkSessionBus()
	printCheck("session bus", sessionBusErr)
	if sessionBusErr != nil {
		failed = true
	}

	secretServiceErr := checkSecretServiceName()
	if dbusErrorName(secretServiceErr) == "org.freedesktop.DBus.Error.NameHasNoOwner" {
		activatable, activatableErr := checkSecretServiceActivatable()
		switch {
		case activatableErr != nil:
			printCheck("secret service", activatableErr)
			failed = true
		case activatable:
			fmt.Printf(
				"%-28s %s: service is activatable but not running yet; it will be started on first access\n",
				"secret service",
				colorize("unknown", colorYellow),
			)
		default:
			printCheck(
				"secret service",
				errors.New("service has no owner and is not activatable"),
			)
			failed = true
		}
	} else {
		printCheck("secret service", secretServiceErr)
		if secretServiceErr != nil {
			failed = true
		}
	}

	// The collection comes from -collection, then from metadata while the
	// recorded object still exists, and finally from the current default alias.
	// Every failure is diagnostic only so doctor remains useful when the
	// Secret Service is unavailable.
	collection := cfg.collection
	recordedCollection := ""

	statePermissionsErr := checkExistingStatePermissions(cfg)
	if statePermissionsErr != nil {
		printCheck("enrollment state permissions", statePermissionsErr)
	} else if collection == "" {
		if md, err := readMetadata(cfg); err == nil {
			recordedCollection = md.Collection
		} else if !errors.Is(err, os.ErrNotExist) {
			printCheck(
				"enrollment metadata",
				err,
			)
		}
	}

	if collection == "" && recordedCollection != "" {
		if err := validateDBusObjectPath(recordedCollection); err != nil {
			printCheck(
				"recorded collection path",
				err,
			)
			failed = true
		} else if locked, err := collectionLocked(
			recordedCollection,
		); err == nil {
			collection = recordedCollection
			fmt.Printf(
				"%-28s %s locked=%v\n",
				"collection locked property",
				colorize("ok", colorGreen),
				locked,
			)
		} else {
			printCheck(
				"recorded collection",
				err,
			)
			failed = true
		}
	}

	if collection == "" {
		c, err := readDefaultCollection()

		printCheck(
			"default collection alias",
			err,
		)
		if err != nil {
			failed = true
		}

		if err == nil {
			collection = c
		}
	}

	if collection != "" && collection != recordedCollection {
		if locked, err := collectionLocked(
			collection,
		); err != nil {
			printCheck(
				"collection locked property",
				err,
			)
			failed = true
		} else {
			fmt.Printf(
				"%-28s %s locked=%v\n",
				"collection locked property",
				colorize("ok", colorGreen),
				locked,
			)
		}
	}

	if listed, err := privateUnlockInterfaceListed(); err != nil {
		fmt.Printf(
			"%-28s %s: %v\n",
			"private unlock interface",
			colorize("unknown", colorYellow),
			err,
		)
	} else if listed {
		fmt.Printf(
			"%-28s %s\n",
			"private unlock interface",
			colorize("listed", colorGreen),
		)
	} else {
		fmt.Printf(
			"%-28s %s\n",
			"private unlock interface",
			colorize("not listed by introspection (informational; the call may still work)", colorYellow),
		)
	}

	fmt.Println()
	fmt.Println(
		colorize("State", colorBold),
	)

	printStatePermissionsCheck(cfg)
	if statePermissionsErr != nil {
		failed = true
	}

	fmt.Println()
	fmt.Println(
		colorize("Security notes", colorBold),
	)

	printSecurityNotes(cfg)

	if failed {
		return errors.New("doctor found one or more failed checks")
	}

	return nil
}

func printSecurityNotes(cfg config) {
	notes := []string{
		"The sealed secret has a PCR policy only (no PIN/authValue): any process able to use " +
			"/dev/tpmrm0 while the PCRs match can unseal it.",
		"If the keyring password equals your login password, that password is what is sealed.",
		"Unlock uses gnome-keyring's private, explicitly unsupported D-Bus interface; it may change between versions.",
		"The secret crosses the session bus in a 'plain' Secret Service session (not encrypted on the bus).",
	}

	if validatePCRSelection(cfg.pcrs) == nil &&
		pcrSelectionOnlyPCR7(cfg.pcrs) {
		notes = append(
			notes,
			"PCR 7 reflects Secure Boot state only; it does not measure the kernel, initramfs or command line. "+
				"Whether that is enough depends on your boot chain.",
		)
	}

	for _, note := range notes {
		fmt.Println(
			colorize("-", colorYellow),
			note,
		)
	}
}

// pcrSelectionOnlyPCR7 reports whether a (validated) selection consists of
// PCR 7 only.
func pcrSelectionOnlyPCR7(selection string) bool {
	for _, bank := range strings.Split(selection, "+") {
		parts := strings.Split(bank, ":")
		if len(parts) != 2 {
			return false
		}

		for _, index := range strings.Split(parts[1], ",") {
			if index != "7" {
				return false
			}
		}
	}

	return true
}

// ---------------------------------------------------------------------------
// TPM unseal / persistent object helpers
// ---------------------------------------------------------------------------

func unsealSecret(
	cfg config,
	md metadata,
) ([]byte, error) {
	if md.Handle == "" {
		return nil, errors.New(
			"metadata has no persistent TPM handle; re-run enroll",
		)
	}

	state, err := inspectPersistent(
		md.Handle,
		md.HandleName,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"inspect persistent sealed object %s: %w",
			md.Handle,
			err,
		)
	}

	switch state {
	case handleAbsent:
		return nil, fmt.Errorf(
			"persistent sealed object %s is absent; re-run enroll",
			md.Handle,
		)

	case handleForeign:
		return nil, fmt.Errorf(
			"persistent handle %s contains a different TPM object; "+
				"refusing to unseal",
			md.Handle,
		)

	case handleUnverified:
		return nil, fmt.Errorf(
			"persistent handle %s cannot be verified; "+
				"metadata has no TPM Name",
			md.Handle,
		)

	case handleOurs:
		// Continue.

	default:
		return nil, fmt.Errorf(
			"unknown persistent handle state for %s",
			md.Handle,
		)
	}

	secret, err := unsealPersistent(
		md.Handle,
		cfg.pcrs,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"persistent sealed object %s could not be unsealed "+
				"(PCR policy not satisfied, e.g. Secure Boot state changed?): %w",
			md.Handle,
			err,
		)
	}

	// The Name check above and tpm2_unseal are separate TPM commands. Checking
	// the Name again afterwards narrows the window in which the object at the
	// handle could have been swapped in between; a swapped object yields a
	// secret that would only fail to unlock the keyring, and it is discarded.
	after, nameErr := persistentObjectName(
		md.Handle,
	)

	if nameErr != nil {
		releaseSecretBuf(secret)

		return nil, fmt.Errorf(
			"re-verify persistent object Name after unseal: %w",
			nameErr,
		)
	}

	if !strings.EqualFold(
		after,
		md.HandleName,
	) {
		releaseSecretBuf(secret)

		return nil, fmt.Errorf(
			"persistent handle %s changed during unseal; discarding the secret",
			md.Handle,
		)
	}

	return secret, nil
}

// finishUnseal validates the unseal output size and hands out the secret.
// The buffer is preallocated large enough that bytes.Buffer never reallocates
// (which would leave an un-zeroed copy of the secret behind).
func finishUnseal(
	out *bytes.Buffer,
	backing []byte,
) ([]byte, error) {
	n := out.Len()

	if n == 0 ||
		n > maxSealedSecretSize {
		zero(out.Bytes())
		releaseSecretBuf(backing)

		return nil, fmt.Errorf(
			"tpm2_unseal returned %d bytes; expected 1..%d",
			n,
			maxSealedSecretSize,
		)
	}

	return out.Bytes(), nil
}

func unsealPersistent(
	handle,
	pcrs string,
) ([]byte, error) {
	if err := requireCommands(
		"tpm2_unseal",
	); err != nil {
		return nil, err
	}

	if err := validatePersistentHandle(handle); err != nil {
		return nil, err
	}

	if err := validatePCRSelection(pcrs); err != nil {
		return nil, fmt.Errorf(
			"invalid PCR selection %q: %w",
			pcrs,
			err,
		)
	}

	backing := newSecretBuf(unsealBufferSize)
	out := bytes.NewBuffer(backing[:0])

	if err := runCmdOut(
		out,
		nil,
		"tpm2_unseal",
		"-c", handle,
		"-p", "pcr:"+pcrs,
	); err != nil {
		zero(out.Bytes())
		releaseSecretBuf(backing)

		return nil, err
	}

	return finishUnseal(out, backing)
}

func unsealLoaded(
	keyCtx,
	pcrs string,
) ([]byte, error) {
	if err := requireCommands(
		"tpm2_startauthsession",
		"tpm2_policypcr",
		"tpm2_flushcontext",
		"tpm2_unseal",
	); err != nil {
		return nil, err
	}

	if err := validatePCRSelection(pcrs); err != nil {
		return nil, fmt.Errorf(
			"invalid PCR selection %q: %w",
			pcrs,
			err,
		)
	}

	tmp, err := os.MkdirTemp(
		"",
		appName+"-selftest-",
	)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	sessionCtx := filepath.Join(
		tmp,
		"session.ctx",
	)

	if err := runCmd(
		nil,
		"tpm2_startauthsession",
		"--policy-session",
		"-S", sessionCtx,
		"-g", "sha256",
	); err != nil {
		return nil, err
	}

	// Best-effort flush; it fails harmlessly when tpm2_unseal already
	// consumed the session.
	defer func() {
		_ = runCmd(
			nil,
			"tpm2_flushcontext",
			sessionCtx,
		)
	}()

	if err := runCmd(
		nil,
		"tpm2_policypcr",
		"-S", sessionCtx,
		"-l", pcrs,
	); err != nil {
		return nil, err
	}

	backing := newSecretBuf(unsealBufferSize)
	out := bytes.NewBuffer(backing[:0])

	if err := runCmdOut(
		out,
		nil,
		"tpm2_unseal",
		"-c", keyCtx,
		"-p", "session:"+sessionCtx,
	); err != nil {
		zero(out.Bytes())
		releaseSecretBuf(backing)

		return nil, err
	}

	return finishUnseal(out, backing)
}

func persistentHandleExists(
	handle string,
) (bool, error) {
	if err := validatePersistentHandle(handle); err != nil {
		return false, err
	}

	handles, err := persistentHandles()
	if err != nil {
		return false, err
	}

	value, err := strconv.ParseUint(handle[2:], 16, 32)
	if err != nil {
		return false, err
	}

	_, exists := handles[value]
	return exists, nil
}

func persistentHandles() (map[uint64]struct{}, error) {
	var out bytes.Buffer

	if err := runCmdOut(
		&out,
		nil,
		"tpm2_getcap",
		"handles-persistent",
	); err != nil {
		return nil, err
	}

	handles := make(map[uint64]struct{})
	for _, field := range strings.Fields(out.String()) {
		if !handleRE.MatchString(field) {
			continue
		}

		value, err := strconv.ParseUint(field[2:], 16, 32)
		if err == nil {
			handles[value] = struct{}{}
		}
	}

	return handles, nil
}

func persistentSlotsAvailable() (uint64, error) {
	var out bytes.Buffer

	if err := runCmdOut(
		&out,
		nil,
		"tpm2_getcap",
		"properties-variable",
	); err != nil {
		return 0, err
	}

	return parsePersistentSlotsAvailable(out.String())
}

func parsePersistentSlotsAvailable(output string) (uint64, error) {
	const property = "TPM2_PT_HR_PERSISTENT_AVAIL:"

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, property) {
			continue
		}

		value := strings.TrimSpace(strings.TrimPrefix(line, property))
		parsed, err := strconv.ParseUint(strings.TrimPrefix(value, "0x"), 16, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid %s value %q: %w", property, value, err)
		}

		return parsed, nil
	}

	return 0, fmt.Errorf("%s was not reported by tpm2_getcap properties-variable", property)
}

func allocatePersistentHandle(handles map[uint64]struct{}) (string, error) {
	for value := dynamicHandleFirst; value <= dynamicHandleLast; value++ {
		if _, occupied := handles[value]; occupied {
			continue
		}

		return fmt.Sprintf("0x%08x", value), nil
	}

	return "", fmt.Errorf(
		"no free persistent handle in range 0x%08x..0x%08x",
		dynamicHandleFirst,
		dynamicHandleLast,
	)
}

// objectName returns the TPM Name (hex) of an object referenced by a context
// file or a persistent handle.
func objectName(
	ref string,
) (string, error) {
	tmp, err := os.MkdirTemp(
		"",
		appName+"-name-",
	)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	nameFile := filepath.Join(
		tmp,
		"name.bin",
	)

	if err := runCmd(
		nil,
		"tpm2_readpublic",
		"-c", ref,
		"-n", nameFile,
	); err != nil {
		return "", err
	}

	raw, err := os.ReadFile(nameFile)
	if err != nil {
		return "", err
	}

	if len(raw) == 0 {
		return "", errors.New(
			"tpm2_readpublic produced an empty Name",
		)
	}

	name := hex.EncodeToString(raw)

	if err := validateTPMName(name); err != nil {
		return "", fmt.Errorf(
			"tpm2_readpublic produced invalid TPM Name: %w",
			err,
		)
	}

	return name, nil
}

func persistentObjectName(
	handle string,
) (string, error) {
	if err := validatePersistentHandle(handle); err != nil {
		return "", err
	}

	return objectName(handle)
}

// classifyPersistentState is deliberately pure.
//
// It contains the security decision about whether the object at a
// persistent handle is absent, ours, foreign, or unverified.
// TPM/D-Bus access is intentionally kept outside this function so the
// classification can be unit-tested without real hardware.
func classifyPersistentState(
	exists bool,
	wantName,
	gotName string,
) handleStatus {
	if !exists {
		return handleAbsent
	}

	if wantName == "" {
		return handleUnverified
	}

	if gotName == "" {
		return handleUnverified
	}

	if strings.EqualFold(
		gotName,
		wantName,
	) {
		return handleOurs
	}

	return handleForeign
}

// inspectPersistent compares the object at handle with the enrolled Name.
//
// A non-nil error means that the TPM could not be queried.
func inspectPersistent(
	handle,
	wantName string,
) (handleStatus, error) {
	if err := validatePersistentHandle(handle); err != nil {
		return handleAbsent, err
	}

	exists, err := persistentHandleExists(
		handle,
	)
	if err != nil {
		return handleAbsent, err
	}

	if !exists {
		return handleAbsent, nil
	}

	if wantName == "" {
		return handleUnverified, nil
	}

	got, err := persistentObjectName(
		handle,
	)
	if err != nil {
		return handleUnverified, err
	}

	return classifyPersistentState(
		true,
		wantName,
		got,
	), nil
}

func evictPersistent(
	handle string,
) error {
	if err := validatePersistentHandle(handle); err != nil {
		return err
	}

	return runCmd(
		nil,
		"tpm2_evictcontrol",
		"-C", "o",
		"-c", handle,
	)
}

func removePersistent(
	handle,
	wantName string,
) error {
	if err := requireCommands(
		"tpm2_getcap",
		"tpm2_readpublic",
		"tpm2_evictcontrol",
	); err != nil {
		return err
	}

	state, err := inspectPersistent(
		handle,
		wantName,
	)
	if err != nil {
		return err
	}

	switch state {
	case handleAbsent:
		return nil

	case handleForeign:
		return fmt.Errorf(
			"persistent handle %s holds a different object; refusing to evict it",
			handle,
		)

	case handleUnverified:
		return fmt.Errorf(
			"persistent handle %s is occupied but its identity cannot be verified; refusing to evict it",
			handle,
		)

	case handleOurs:
		// TPM2 tools do not expose an atomic "evict only if Name matches"
		// operation. Re-check immediately before eviction and verify the result
		// afterwards to narrow and detect a handle replacement.
		latest, err := inspectPersistent(handle, wantName)
		if err != nil {
			return err
		}
		if latest != handleOurs {
			return fmt.Errorf(
				"persistent handle %s changed before eviction; refusing to evict it",
				handle,
			)
		}

		if err := evictPersistent(handle); err != nil {
			return err
		}

		state, err := inspectPersistent(handle, wantName)
		if err != nil {
			return fmt.Errorf(
				"verify persistent handle %s after eviction: %w",
				handle,
				err,
			)
		}
		if state != handleAbsent {
			return fmt.Errorf(
				"persistent handle %s is occupied after eviction (%s); inspect it manually",
				handle,
				state,
			)
		}

		return nil

	default:
		return fmt.Errorf(
			"unknown persistent handle state for %s",
			handle,
		)
	}
}

// ---------------------------------------------------------------------------
// Metadata and validation
// ---------------------------------------------------------------------------

func ensureStateDir(cfg config) error {
	if err := rejectSymlinkComponents(cfg.dir); err != nil {
		return err
	}

	if err := os.MkdirAll(
		cfg.dir,
		0700,
	); err != nil {
		return err
	}

	info, err := os.Lstat(
		cfg.dir,
	)
	if err != nil {
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%s must not be a symlink",
			cfg.dir,
		)
	}

	if !info.IsDir() {
		return fmt.Errorf(
			"%s is not a directory",
			cfg.dir,
		)
	}

	if err := os.Chmod(
		cfg.dir,
		0700,
	); err != nil {
		return err
	}

	return checkStatePermissions(cfg)
}

// rejectSymlinkComponents rejects symlinked components of an existing path.
func rejectSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("path %q is not absolute", path)
	}

	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(clean, current), string(filepath.Separator)) {
		if component == "" {
			continue
		}

		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must not contain symlink %s", path, current)
		}
	}

	return nil
}

func writeMetadata(
	cfg config,
	handle,
	handleName string,
) error {
	if err := validatePersistentHandle(handle); err != nil {
		return err
	}

	if err := validateTPMName(handleName); err != nil {
		return fmt.Errorf(
			"invalid TPM object Name: %w",
			err,
		)
	}

	if err := validateDBusObjectPath(cfg.collection); err != nil {
		return fmt.Errorf(
			"invalid Secret Service collection path: %w",
			err,
		)
	}

	if err := validatePCRSelection(cfg.pcrs); err != nil {
		return fmt.Errorf(
			"invalid PCR selection: %w",
			err,
		)
	}

	md := metadata{
		Version:    metadataVersion,
		App:        appName,
		CreatedAt:  time.Now().UTC(),
		Collection: cfg.collection,
		PCRs:       cfg.pcrs,
		Handle:     handle,
		HandleName: handleName,
	}

	if err := validateMetadata(md); err != nil {
		return fmt.Errorf(
			"metadata validation failed: %w",
			err,
		)
	}

	data, err := json.MarshalIndent(
		md,
		"",
		"  ",
	)
	if err != nil {
		return err
	}

	data = append(
		data,
		'\n',
	)

	if err := ensureStateDir(cfg); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(
		cfg.dir,
		".metadata.json.tmp-*",
	)
	if err != nil {
		return err
	}

	tmpPath := tmpFile.Name()

	cleanup := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}

	if err := tmpFile.Chmod(0600); err != nil {
		cleanup()
		return err
	}

	if _, err := tmpFile.Write(
		data,
	); err != nil {
		cleanup()
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		cleanup()
		return err
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(
		tmpPath,
		cfg.metadata,
	); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := syncDir(cfg.dir); err != nil {
		return err
	}

	return checkPathPerm(
		cfg.metadata,
		0600,
	)
}

func readMetadata(
	cfg config,
) (metadata, error) {
	var md metadata

	if err := checkExistingStatePermissions(cfg); err != nil {
		return md, fmt.Errorf("state permissions: %w", err)
	}

	stateFD, err := unix.Open(
		cfg.dir,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return md, err
	}
	defer syscall.Close(stateFD)

	var stateStat syscall.Stat_t
	if err := syscall.Fstat(stateFD, &stateStat); err != nil {
		return md, err
	}
	if err := validateStateStat(&stateStat, cfg.dir); err != nil {
		return md, err
	}

	metadataFD, err := unix.Openat(
		stateFD,
		"metadata.json",
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return md, err
	}
	metadataFile := os.NewFile(uintptr(metadataFD), cfg.metadata)
	if metadataFile == nil {
		_ = syscall.Close(metadataFD)
		return md, errors.New("could not create metadata file handle")
	}
	defer metadataFile.Close()

	var metadataStat syscall.Stat_t
	if err := syscall.Fstat(metadataFD, &metadataStat); err != nil {
		return md, err
	}
	if err := validateMetadataStat(&metadataStat, cfg.metadata); err != nil {
		return md, err
	}

	data, err := io.ReadAll(io.LimitReader(metadataFile, maxMetadataSize+1))
	if err != nil {
		return md, err
	}
	if len(data) > maxMetadataSize {
		return md, fmt.Errorf("metadata exceeds %d bytes", maxMetadataSize)
	}

	if err := json.Unmarshal(
		data,
		&md,
	); err != nil {
		return md, err
	}

	return md, nil
}

func validateStateStat(stat *syscall.Stat_t, path string) error {
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("%s is not a directory", path)
	}
	if stat.Mode&0777 != 0700 {
		return fmt.Errorf("%s has permissions %04o, want 0700", path, stat.Mode&0777)
	}
	if uint64(stat.Uid) != uint64(os.Getuid()) {
		return fmt.Errorf("%s is owned by UID %d, want UID %d", path, stat.Uid, os.Getuid())
	}

	return nil
}

func validateMetadataStat(stat *syscall.Stat_t, path string) error {
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if stat.Mode&0777 != 0600 {
		return fmt.Errorf("%s has permissions %04o, want 0600", path, stat.Mode&0777)
	}
	if uint64(stat.Uid) != uint64(os.Getuid()) {
		return fmt.Errorf("%s is owned by UID %d, want UID %d", path, stat.Uid, os.Getuid())
	}

	return nil
}

func enrollmentMetadata(
	cfg config,
) (metadata, error) {
	md, err := readMetadata(
		cfg,
	)
	if err != nil {
		return metadata{}, fmt.Errorf(
			"metadata unreadable: %w",
			err,
		)
	}

	if err := validateMetadata(md); err != nil {
		return metadata{}, err
	}

	return md, nil
}

// validateMetadata validates all durable metadata fields that influence
// TPM selection, Secret Service access, or persistent-object identity.
func validateMetadata(md metadata) error {
	if md.Version != metadataVersion {
		return fmt.Errorf(
			"unsupported metadata version %d, want %d; run %s purge then %s enroll; %s",
			md.Version,
			metadataVersion,
			appName,
			appName,
			forgetHint(),
		)
	}

	if md.App != appName {
		return fmt.Errorf(
			"metadata app mismatch: got %q, want %q",
			md.App,
			appName,
		)
	}

	if md.CreatedAt.IsZero() {
		return errors.New(
			"metadata missing created_at",
		)
	}

	if err := validateDBusObjectPath(md.Collection); err != nil {
		return fmt.Errorf(
			"metadata has invalid collection object path %q: %w",
			md.Collection,
			err,
		)
	}

	if err := validatePCRSelection(md.PCRs); err != nil {
		return fmt.Errorf(
			"metadata has invalid PCR selection %q: %w",
			md.PCRs,
			err,
		)
	}

	if err := validatePersistentHandle(md.Handle); err != nil {
		return fmt.Errorf(
			"metadata has invalid persistent handle %q: %w",
			md.Handle,
			err,
		)
	}

	if err := validateTPMName(md.HandleName); err != nil {
		return fmt.Errorf(
			"metadata has invalid persistent TPM Name: %w",
			err,
		)
	}

	return nil
}

// validatePersistentHandle validates a TPM persistent object handle that
// this tool can create with the owner hierarchy.
//
// Owner-hierarchy persistent handles occupy 0x81000000..0x817FFFFF; the
// upper half (0x81800000..0x81FFFFFF) is platform-controlled and cannot be
// used with "tpm2_evictcontrol -C o".
func validatePersistentHandle(handle string) error {
	if !handleRE.MatchString(handle) {
		return fmt.Errorf(
			"invalid persistent handle format",
		)
	}

	value, err := strconv.ParseUint(
		handle[2:],
		16,
		32,
	)
	if err != nil {
		return fmt.Errorf(
			"invalid persistent handle %q: %w",
			handle,
			err,
		)
	}

	if value < persistentOwnerFirst ||
		value > persistentOwnerLast {
		return fmt.Errorf(
			"handle %q is outside the owner-hierarchy persistent handle range 0x%08x..0x%08x",
			handle,
			persistentOwnerFirst,
			persistentOwnerLast,
		)
	}

	return nil
}

// validatePCRSelection validates the PCR selection syntax used by
// tpm2-tools for this program.
//
// Accepted examples:
//
//	sha256:7
//	sha256:0,1,7
//	sha256:0,1+sha1:7
//
// PCR indices are restricted to the standard TPM PCR range 0..23.
//
// The syntax is deliberately strict: whitespace is not accepted,
// PCR banks cannot be repeated, and a PCR index cannot occur twice
// within the same bank.
func validatePCRSelection(selection string) error {
	if selection == "" {
		return errors.New("PCR selection must not be empty")
	}

	seenBanks := make(map[string]struct{})
	seenIndices := make(map[string]map[int]struct{})

	for _, bankSelection := range strings.Split(selection, "+") {
		parts := strings.Split(bankSelection, ":")
		if len(parts) != 2 {
			return fmt.Errorf(
				"invalid PCR selection %q, want BANK:INDEX[,INDEX...]",
				selection,
			)
		}

		bank := strings.ToLower(parts[0])
		if bank == "" {
			return fmt.Errorf("PCR bank must not be empty")
		}

		if parts[0] != strings.TrimSpace(parts[0]) ||
			parts[1] != strings.TrimSpace(parts[1]) {
			return fmt.Errorf(
				"PCR selection %q must not contain whitespace",
				selection,
			)
		}

		if _, ok := pcrBankNames[bank]; !ok {
			return fmt.Errorf(
				"unsupported PCR bank %q, want one of sha1, sha256, sha384, sha512",
				parts[0],
			)
		}

		if _, exists := seenBanks[bank]; exists {
			return fmt.Errorf(
				"PCR bank %q is specified more than once",
				parts[0],
			)
		}
		seenBanks[bank] = struct{}{}

		if seenIndices[bank] == nil {
			seenIndices[bank] = make(map[int]struct{})
		}

		for _, indexText := range strings.Split(parts[1], ",") {
			if indexText == "" {
				return fmt.Errorf(
					"invalid PCR index in selection %q",
					selection,
				)
			}

			for _, r := range indexText {
				if r < '0' || r > '9' {
					return fmt.Errorf(
						"invalid PCR index %q in selection %q",
						indexText,
						selection,
					)
				}
			}

			index, err := strconv.Atoi(indexText)
			if err != nil {
				return fmt.Errorf(
					"invalid PCR index %q: %w",
					indexText,
					err,
				)
			}

			if index < 0 || index > maxPCRIndex {
				return fmt.Errorf(
					"PCR index %d is outside supported range 0..%d",
					index,
					maxPCRIndex,
				)
			}

			if _, exists := seenIndices[bank][index]; exists {
				return fmt.Errorf(
					"PCR %s:%d is specified more than once",
					bank,
					index,
				)
			}
			seenIndices[bank][index] = struct{}{}
		}
	}

	return nil
}

// validateDBusObjectPath validates a D-Bus object path according to the
// object-path grammar relevant to Secret Service collection paths.
func validateDBusObjectPath(path string) error {
	if path == "" {
		return errors.New(
			"D-Bus object path is empty",
		)
	}

	if len(path) > maxDBusObjectPath {
		return fmt.Errorf(
			"D-Bus object path is %d bytes; maximum is %d",
			len(path),
			maxDBusObjectPath,
		)
	}

	if path[0] != '/' {
		return errors.New(
			"D-Bus object path must start with '/'",
		)
	}

	if path == "/" {
		return errors.New(
			"Secret Service collection path cannot be root '/'",
		)
	}

	if strings.Contains(path, "//") {
		return errors.New(
			"D-Bus object path contains an empty element",
		)
	}

	for _, element := range strings.Split(
		path[1:],
		"/",
	) {
		if element == "" {
			return errors.New(
				"D-Bus object path contains an empty element",
			)
		}

		for _, r := range element {
			switch {
			case r >= 'A' && r <= 'Z':
			case r >= 'a' && r <= 'z':
			case r >= '0' && r <= '9':
			case r == '_':
			default:
				return fmt.Errorf(
					"D-Bus object path contains invalid character %q",
					r,
				)
			}
		}
	}

	return nil
}

// validateTPMName validates the serialized TPM Name returned by
// tpm2_readpublic -n.
//
// A TPM Name is binary data represented here as hexadecimal text.
// The first two bytes identify the name hash algorithm, followed by
// the digest. Therefore it must contain at least four bytes and have
// an even number of hexadecimal characters.
func validateTPMName(name string) error {
	name = strings.TrimSpace(name)

	if name == "" {
		return errors.New(
			"TPM Name is empty",
		)
	}

	raw, err := hex.DecodeString(name)
	if err != nil {
		return fmt.Errorf(
			"TPM Name is not valid hexadecimal: %w",
			err,
		)
	}

	if len(raw) < 2 {
		return errors.New("TPM Name is too short")
	}

	digestSizes := map[uint16]int{
		0x0004: 20, // SHA-1
		0x000b: 32, // SHA-256
		0x000c: 48, // SHA-384
		0x000d: 64, // SHA-512
		0x0012: 32, // SM3-256
		0x0027: 32, // SHA3-256
		0x0028: 48, // SHA3-384
		0x0029: 64, // SHA3-512
	}

	nameAlg := uint16(raw[0])<<8 | uint16(raw[1])
	digestSize, ok := digestSizes[nameAlg]
	if !ok {
		return fmt.Errorf("TPM Name uses unsupported nameAlg 0x%04x", nameAlg)
	}

	if len(raw[2:]) != digestSize {
		return fmt.Errorf(
			"TPM Name nameAlg 0x%04x requires %d-byte digest, got %d",
			nameAlg,
			digestSize,
			len(raw[2:]),
		)
	}

	return nil
}

func checkStatePermissions(
	cfg config,
) error {
	if err := checkPathPerm(
		cfg.dir,
		0700,
	); err != nil {
		return err
	}

	if _, err := os.Lstat(
		cfg.metadata,
	); errors.Is(
		err,
		os.ErrNotExist,
	) {
		return nil
	} else if err != nil {
		return err
	}

	return checkPathPerm(
		cfg.metadata,
		0600,
	)
}

func syncDir(path string) error {
	dirFile, err := os.Open(path)
	if err != nil {
		return err
	}

	syncErr := dirFile.Sync()
	closeErr := dirFile.Close()

	if syncErr != nil {
		return syncErr
	}

	if closeErr != nil {
		return closeErr
	}

	return nil
}

// checkExistingStatePermissions verifies the existing state path without
// creating anything.
//
// This function is intentionally separate from ensureStateDir:
//
//   - ensureStateDir() is used when creating/enrolling state;
//   - checkExistingStatePermissions() is used before reading/removing
//     existing state.
//
// Most importantly, it rejects a symlinked state directory BEFORE callers
// access cfg.metadata or remove files below cfg.dir.
func checkExistingStatePermissions(
	cfg config,
) error {
	if err := rejectSymlinkComponents(cfg.dir); err != nil {
		return err
	}

	info, err := os.Lstat(
		cfg.dir,
	)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%s must not be a symlink",
			cfg.dir,
		)
	}

	if !info.IsDir() {
		return fmt.Errorf(
			"%s is not a directory",
			cfg.dir,
		)
	}

	if err := checkPathPerm(
		cfg.dir,
		0700,
	); err != nil {
		return err
	}

	if _, err := os.Lstat(
		cfg.metadata,
	); errors.Is(
		err,
		os.ErrNotExist,
	) {
		return nil
	} else if err != nil {
		return err
	}

	return checkPathPerm(
		cfg.metadata,
		0600,
	)
}

func checkPathPerm(
	path string,
	want os.FileMode,
) error {
	info, err := os.Lstat(
		path,
	)
	if err != nil {
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%s must not be a symlink",
			path,
		)
	}

	got := info.Mode().Perm()

	if got != want {
		return fmt.Errorf(
			"%s has permissions %04o, want %04o",
			path,
			got,
			want,
		)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}

	currentUID := uint64(
		os.Getuid(),
	)

	if uint64(stat.Uid) != currentUID {
		return fmt.Errorf(
			"%s is owned by UID %d, want UID %d",
			path,
			stat.Uid,
			currentUID,
		)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Secret Service (D-Bus)
// ---------------------------------------------------------------------------

// unlockCollection sends the master password to gnome-keyring over the
// session bus using a "plain" Secret Service session (the secret is not
// encrypted on the bus). Any copies made while marshalling the D-Bus message
// cannot be zeroed from Go.
//
// NOTE: on an already unlocked collection this call succeeds without
// validating the password; use verifyKeyringPassword when correctness of the
// password matters.
func unlockCollection(
	collection string,
	secret []byte,
) error {
	if err := validateDBusObjectPath(collection); err != nil {
		return markPermanent(fmt.Errorf(
			"invalid collection object path: %w",
			err,
		))
	}

	conn, err := dbusConn()
	if err != nil {
		return err
	}
	defer conn.Close()

	obj := conn.Object(
		secretServiceName,
		dbus.ObjectPath(secretServicePath),
	)

	var output dbus.Variant
	var session dbus.ObjectPath

	if err := obj.Call(
		"org.freedesktop.Secret.Service.OpenSession",
		0,
		"plain",
		dbus.MakeVariant(""),
	).Store(
		&output,
		&session,
	); err != nil {
		return fmt.Errorf(
			"OpenSession failed: %w",
			classifyDBusError(err),
		)
	}

	defer func() {
		sessionObj := conn.Object(
			secretServiceName,
			session,
		)

		_ = sessionObj.Call(
			"org.freedesktop.Secret.Session.Close",
			0,
		).Err
	}()

	dbusSecret := secretValue{
		Session:     session,
		Parameters:  []byte{},
		Value:       secret,
		ContentType: "text/plain",
	}

	if err := obj.Call(
		privateUnlockInterface+".UnlockWithMasterPassword",
		0,
		dbus.ObjectPath(collection),
		dbusSecret,
	).Err; err != nil {
		return fmt.Errorf(
			"UnlockWithMasterPassword failed: %w",
			classifyDBusError(err),
		)
	}

	return nil
}

// lockCollection locks a collection through the standard Secret Service
// Lock method.
func lockCollection(
	collection string,
) error {
	if err := validateDBusObjectPath(collection); err != nil {
		return markPermanent(fmt.Errorf(
			"invalid collection object path: %w",
			err,
		))
	}

	conn, err := dbusConn()
	if err != nil {
		return err
	}
	defer conn.Close()

	obj := conn.Object(
		secretServiceName,
		dbus.ObjectPath(secretServicePath),
	)

	var locked []dbus.ObjectPath
	var prompt dbus.ObjectPath

	if err := obj.Call(
		"org.freedesktop.Secret.Service.Lock",
		0,
		[]dbus.ObjectPath{dbus.ObjectPath(collection)},
	).Store(
		&locked,
		&prompt,
	); err != nil {
		return fmt.Errorf(
			"Lock failed: %w",
			classifyDBusError(err),
		)
	}

	return nil
}

func unlockCollectionWithRetry(
	collection string,
	secret []byte,
	timeout time.Duration,
) error {
	return withRetry(
		timeout,
		func() error {
			return unlockCollection(
				collection,
				secret,
			)
		},
	)
}

func collectionLocked(
	collection string,
) (bool, error) {
	if err := validateDBusObjectPath(collection); err != nil {
		return false, markPermanent(fmt.Errorf(
			"invalid collection object path: %w",
			err,
		))
	}

	conn, err := dbusConn()
	if err != nil {
		return false, err
	}
	defer conn.Close()

	obj := conn.Object(
		secretServiceName,
		dbus.ObjectPath(collection),
	)

	var lockedVariant dbus.Variant

	if err := obj.Call(
		"org.freedesktop.DBus.Properties.Get",
		0,
		"org.freedesktop.Secret.Collection",
		"Locked",
	).Store(
		&lockedVariant,
	); err != nil {
		return false, fmt.Errorf(
			"Properties.Get Locked failed: %w",
			classifyDBusError(err),
		)
	}

	locked, ok := lockedVariant.Value().(bool)
	if !ok {
		return false, markPermanent(fmt.Errorf(
			"Properties.Get Locked returned %T, want bool",
			lockedVariant.Value(),
		))
	}

	return locked, nil
}

func collectionLockedWithRetry(
	collection string,
	timeout time.Duration,
) (bool, error) {
	var locked bool

	err := withRetry(
		timeout,
		func() error {
			var err error

			locked, err = collectionLocked(
				collection,
			)

			return err
		},
	)

	return locked, err
}

// withRetry retries fn until it succeeds or the timeout expires, but only
// as long as retrying can help:
//   - permanent errors are returned immediately;
//   - transient errors (service or object not there yet) are retried until
//     the timeout;
//   - anything else (for example a rejected password) is retried at most
//     maxUnclassifiedAttempts times.
func withRetry(
	timeout time.Duration,
	fn func() error,
) error {
	if timeout <= 0 {
		return fn()
	}

	deadline := time.Now().Add(timeout)
	attempts := 0

	for {
		if err := checkInterrupted(); err != nil {
			return err
		}

		attempts++

		err := fn()
		if err == nil {
			return nil
		}

		if isPermanent(err) {
			return err
		}

		if !isTransient(err) &&
			attempts >= maxUnclassifiedAttempts {
			return err
		}

		if time.Now().Add(
			retryInterval,
		).After(deadline) {
			return err
		}

		if sleepErr := sleepInterruptible(retryInterval); sleepErr != nil {
			return sleepErr
		}
	}
}

func checkSessionBus() error {
	conn, err := dbusConn()
	if err != nil {
		return err
	}

	return conn.Close()
}

func checkSecretServiceName() error {
	conn, err := dbusConn()
	if err != nil {
		return err
	}
	defer conn.Close()

	var owner string

	obj := conn.Object(
		"org.freedesktop.DBus",
		dbus.ObjectPath("/org/freedesktop/DBus"),
	)

	if err := obj.Call(
		"org.freedesktop.DBus.GetNameOwner",
		0,
		secretServiceName,
	).Store(&owner); err != nil {
		return err
	}

	if owner == "" {
		return errors.New(
			secretServiceName + " has no owner",
		)
	}

	return nil
}

func checkSecretServiceActivatable() (bool, error) {
	conn, err := dbusConn()
	if err != nil {
		return false, err
	}
	defer conn.Close()

	obj := conn.Object(
		"org.freedesktop.DBus",
		dbus.ObjectPath("/org/freedesktop/DBus"),
	)

	var names []string
	if err := obj.Call(
		"org.freedesktop.DBus.ListActivatableNames",
		0,
	).Store(&names); err != nil {
		return false, err
	}

	return stringInSlice(secretServiceName, names), nil
}

// privateUnlockInterfaceListed reports whether the Secret Service object
// advertises the private gnome-keyring unlock interface in its introspection
// data. The result is informational only.
func privateUnlockInterfaceListed() (bool, error) {
	conn, err := dbusConn()
	if err != nil {
		return false, err
	}
	defer conn.Close()

	obj := conn.Object(
		secretServiceName,
		dbus.ObjectPath(secretServicePath),
	)

	var xml string

	if err := obj.Call(
		"org.freedesktop.DBus.Introspectable.Introspect",
		0,
	).Store(&xml); err != nil {
		return false, err
	}

	return strings.Contains(xml, privateUnlockInterface) &&
		strings.Contains(xml, "UnlockWithMasterPassword"), nil
}

// ---------------------------------------------------------------------------
// TPM device permissions and doctor output helpers
// ---------------------------------------------------------------------------

func checkTPMReady() error {
	if err := runDiagnosticCmd(
		"tpm2_getcap",
		"properties-fixed",
	); err != nil {
		if advice, ok := tpmPermissionAdviceFor(os.Stderr); ok {
			return fmt.Errorf(
				"%w\n\n%s",
				err,
				advice,
			)
		}

		return err
	}

	return nil
}

func printTPMPermissionAdvice() {
	advice, ok := tpmPermissionAdvice()
	if !ok {
		return
	}

	fmt.Println()
	fmt.Println(advice)
}

func tpmDeviceSummary() (string, error) {
	info, err := os.Stat(
		"/dev/tpmrm0",
	)
	if err != nil {
		return "", err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Sprintf(
			"/dev/tpmrm0          mode=%s",
			info.Mode(),
		), nil
	}

	uid := strconv.FormatUint(
		uint64(stat.Uid),
		10,
	)

	gid := strconv.FormatUint(
		uint64(stat.Gid),
		10,
	)

	owner := fallback(
		lookupUsername(uid),
		uid,
	)

	group := fallback(
		lookupGroupName(gid),
		gid,
	)

	return fmt.Sprintf(
		"/dev/tpmrm0          mode=%s owner=%s(%s) group=%s(%s)",
		info.Mode(),
		owner,
		uid,
		group,
		gid,
	), nil
}

func tpmPermissionAdvice() (string, bool) {
	return tpmPermissionAdviceFor(os.Stdout)
}

func tpmPermissionAdviceFor(output *os.File) (string, bool) {
	info, err := os.Stat(
		"/dev/tpmrm0",
	)
	if err != nil {
		return "", false
	}

	if info.Mode().Perm()&0020 == 0 {
		return "", false
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}

	deviceUID := strconv.FormatUint(
		uint64(stat.Uid),
		10,
	)

	deviceGID := strconv.FormatUint(
		uint64(stat.Gid),
		10,
	)

	ownerName := lookupUsername(
		deviceUID,
	)

	groupName := lookupGroupName(
		deviceGID,
	)

	groupForCommand := groupName

	if groupForCommand == "" {
		groupForCommand = deviceGID
	}

	current, err := user.Current()
	if err != nil {
		return "", false
	}

	groupIDs := processGroupIDs()
	accountGroupIDs, _ := current.GroupIds()

	if hasGroupID(
		deviceGID,
		groupIDs,
	) {
		return "", false
	}

	username := current.Username
	if username == "" {
		username = "$USER"
	}

	var b strings.Builder

	fmt.Fprintln(
		&b,
		colorizeFor(
			"TPM permission hint:",
			colorYellow,
			output,
		),
	)

	fmt.Fprintf(
		&b,
		"  /dev/tpmrm0 owner: %s (%s)\n",
		fallback(
			ownerName,
			deviceUID,
		),
		deviceUID,
	)

	fmt.Fprintf(
		&b,
		"  /dev/tpmrm0 group: %s (%s)\n",
		fallback(
			groupName,
			deviceGID,
		),
		deviceGID,
	)

	fmt.Fprintf(
		&b,
		"  /dev/tpmrm0 mode:  %s\n",
		info.Mode(),
	)

	fmt.Fprintf(
		&b,
		"  your groups:       %s\n",
		userGroupSummary(groupIDs),
	)

	if len(accountGroupIDs) > 0 && hasGroupID(deviceGID, accountGroupIDs) {
		fmt.Fprintln(&b)
		fmt.Fprintln(
			&b,
			"This account is already listed in the system group database, but the current session does not yet include that group.",
		)
		fmt.Fprintln(
			&b,
			"Fully log out of the graphical session and log back in, or reboot, before retrying.",
		)

		return strings.TrimRight(b.String(), "\n"), true
	}

	fmt.Fprintln(&b)

	fmt.Fprintln(
		&b,
		"The TPM resource manager is group-writable, but your user is not in that group.",
	)

	fmt.Fprintln(
		&b,
		colorizeFor(
			"Run this exact command:",
			colorYellow,
			output,
		),
	)

	fmt.Fprintf(
		&b,
		"  %s\n",
		colorizeFor(
			fmt.Sprintf(
				"sudo usermod -aG %s %s",
				shellQuote(groupForCommand),
				shellQuote(username),
			),
			colorCyan,
			output,
		),
	)

	fmt.Fprintln(&b)

	fmt.Fprintf(
		&b,
		"Use the device group shown above (%s), not your hostname or username.\n",
		groupForCommand,
	)

	fmt.Fprintln(
		&b,
		"Then fully log out of the graphical session and log back in, or reboot.",
	)

	fmt.Fprintln(
		&b,
		"Starting a new shell or a new login shell is not enough for group membership changes.",
	)

	return strings.TrimRight(
		b.String(),
		"\n",
	), true
}

func lookupUsername(
	uid string,
) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return ""
	}

	return u.Username
}

func lookupGroupName(
	gid string,
) string {
	g, err := user.LookupGroupId(gid)
	if err != nil {
		return ""
	}

	return g.Name
}

func processGroupIDs() []string {
	groups, _ := os.Getgroups()
	out := make([]string, 0, len(groups)+2)
	seen := make(map[string]struct{}, len(groups)+1)
	appendGroup := func(gid int) {
		value := strconv.Itoa(gid)
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}

	for _, gid := range groups {
		appendGroup(gid)
	}

	appendGroup(os.Getgid())

	return out
}

func hasGroupID(
	needle string,
	haystack []string,
) bool {
	return stringInSlice(needle, haystack)
}

func userGroupSummary(
	groupIDs []string,
) string {
	if len(groupIDs) == 0 {
		return "(none)"
	}

	parts := make(
		[]string,
		0,
		len(groupIDs),
	)

	for _, gid := range groupIDs {
		name := lookupGroupName(
			gid,
		)

		if name == "" {
			parts = append(
				parts,
				gid,
			)
			continue
		}

		parts = append(
			parts,
			fmt.Sprintf(
				"%s(%s)",
				name,
				gid,
			),
		)
	}

	return strings.Join(
		parts,
		", ",
	)
}

func stringInSlice(
	needle string,
	haystack []string,
) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}

	return false
}

func fallback(
	value,
	fallbackValue string,
) string {
	if value == "" {
		return fallbackValue
	}

	return value
}

func printCheck(
	name string,
	err error,
) {
	if err != nil {
		fmt.Printf(
			"%-28s %s: %v\n",
			name,
			colorize(
				"fail",
				colorRed,
			),
			err,
		)
		return
	}

	fmt.Printf(
		"%-28s %s\n",
		name,
		colorize(
			"ok",
			colorGreen,
		),
	)
}

func printBool(
	name string,
	ok bool,
) {
	value := colorize(
		"true",
		colorGreen,
	)

	if !ok {
		value = colorize(
			"false",
			colorRed,
		)
	}

	fmt.Printf(
		"%-28s %s\n",
		name,
		value,
	)
}

func printStatePermissionsCheck(
	cfg config,
) {
	if _, err := os.Lstat(
		cfg.dir,
	); errors.Is(
		err,
		os.ErrNotExist,
	) {
		fmt.Printf(
			"%-28s %s %s\n",
			"state permissions",
			colorize(
				"ok",
				colorGreen,
			),
			colorize(
				"(not enrolled yet)",
				colorDim,
			),
		)

		return
	}

	printCheck(
		"state permissions",
		statePermissionsError(cfg),
	)
}

func statePermissionsError(
	cfg config,
) error {
	if _, err := os.Lstat(
		cfg.dir,
	); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}

	return checkStatePermissions(cfg)
}

const (
	colorReset  = "\x1b[0m"
	colorBold   = "\x1b[1m"
	colorDim    = "\x1b[2m"
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorCyan   = "\x1b[36m"
)

func colorize(
	s,
	color string,
) string {
	return colorizeFor(s, color, os.Stdout)
}

func colorizeFor(
	s,
	color string,
	f *os.File,
) string {
	if !colorsEnabledFor(f) {
		return s
	}

	return color +
		s +
		colorReset
}

func colorizeStderr(
	s,
	color string,
) string {
	if !colorsEnabledFor(os.Stderr) {
		return s
	}

	return color + s + colorReset
}

func colorsEnabledFor(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" ||
		os.Getenv("TERM") == "dumb" {
		return false
	}

	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// quoteSystemdArg quotes an argument for a systemd ExecStart= line. Besides
// backslash and double quote, '%' (specifiers) and '$' (variable expansion)
// are escaped so the argument reaches the program unchanged.
func quoteSystemdArg(
	arg string,
) (string, error) {
	if strings.ContainsAny(arg, "\n\r\x00") {
		return "", fmt.Errorf(
			"argument %q contains a control character and cannot be used in a systemd unit",
			arg,
		)
	}

	escaped := strings.NewReplacer(
		`\`,
		`\\`,
		`"`,
		`\"`,
		`%`,
		`%%`,
		`$`,
		`$$`,
	).Replace(arg)

	return `"` +
		escaped +
		`"`, nil
}

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}

	if strings.IndexFunc(arg, func(r rune) bool {
		switch {
		case r >= 'A' && r <= 'Z':
			return false
		case r >= 'a' && r <= 'z':
			return false
		case r >= '0' && r <= '9':
			return false
		case r == '_':
			return false
		case r == '-':
			return false
		case r == '.':
			return false
		default:
			return true
		}
	}) == -1 {
		return arg
	}

	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

// ---------------------------------------------------------------------------
// Running external tools
// ---------------------------------------------------------------------------

func runCmd(
	stdin io.Reader,
	name string,
	args ...string,
) error {
	return runCmdOut(
		io.Discard,
		stdin,
		name,
		args...,
	)
}

func runCmdOut(
	stdout io.Writer,
	stdin io.Reader,
	name string,
	args ...string,
) error {
	path, err := resolveTool(name)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), externalCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		path,
		args...,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	cmd.Env = childEnv()
	cmd.Stdin = stdin
	cmd.Stdout = stdout

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%s timed out after %s", name, externalCommandTimeout)
		}

		return fmt.Errorf(
			"%s failed: %w: %s",
			name,
			err,
			strings.TrimSpace(
				stderr.String(),
			),
		)
	}

	return nil
}

func runDiagnosticCmd(
	name string,
	args ...string,
) error {
	path, err := resolveTool(name)
	if err != nil {
		return fmt.Errorf(
			"%s failed: %w",
			name,
			err,
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), externalCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		path,
		args...,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	cmd.Env = childEnv()
	cmd.Stdout = io.Discard

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%s timed out after %s", name, externalCommandTimeout)
		}

		msg := firstNonEmptyLine(
			stderr.String(),
		)

		if msg == "" {
			msg = err.Error()
		}

		return fmt.Errorf(
			"%s failed: %s",
			name,
			msg,
		)
	}

	return nil
}

func firstNonEmptyLine(
	s string,
) string {
	for _, line := range strings.Split(
		s,
		"\n",
	) {
		line = strings.TrimSpace(
			line,
		)

		if line != "" {
			return line
		}
	}

	return ""
}

// ---------------------------------------------------------------------------
// Password input
// ---------------------------------------------------------------------------

// readPassword reads one line from stdin with echo disabled (when stdin is a
// terminal). The password is read byte by byte into a locked buffer, without
// bufio, so no additional copies of it are left in buffered readers.
//
// An interrupt (signal handler installed by installSignalHandler) aborts the
// read and the terminal state is restored.
func readPassword() ([]byte, error) {
	buf := newSecretBuf(maxPasswordInput)

	fd := int(
		os.Stdin.Fd(),
	)

	oldState, termErr := getTermios(
		fd,
	)

	if termErr == nil {
		newState := oldState

		newState.Lflag &^= syscall.ECHO

		if err := setTermios(
			fd,
			newState,
		); err != nil {
			releaseSecretBuf(buf)

			return nil, err
		}

		defer func() {
			_ = setTermios(
				fd,
				oldState,
			)
		}()
	}

	type result struct {
		n   int
		err error
	}

	done := make(chan result, 1)

	go func() {
		n, err := readLineInto(
			os.Stdin,
			buf[:cap(buf)],
		)

		done <- result{n: n, err: err}
	}()

	select {
	case r := <-done:
		fmt.Println()

		if r.err != nil {
			releaseSecretBuf(buf)

			return nil, r.err
		}

		return buf[:r.n], nil

	case <-interruptCh:
		fmt.Println()

		go func() {
			<-done

			releaseSecretBuf(buf)
		}()

		return nil, errInterrupted
	}
}

// readLineInto reads a single line (up to '\n' or EOF) into buf one byte at
// a time and returns its length without the line terminator. A trailing CR
// is removed. Lines longer than buf are rejected.
func readLineInto(
	r io.Reader,
	buf []byte,
) (int, error) {
	var one [1]byte

	defer func() {
		one[0] = 0
	}()

	n := 0

	for {
		m, err := r.Read(one[:])

		if m == 1 {
			if one[0] == '\n' {
				break
			}

			if n == len(buf) {
				return n, errors.New(
					"input line is too long",
				)
			}

			buf[n] = one[0]
			n++
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return n, err
		}
	}

	for n > 0 &&
		buf[n-1] == '\r' {
		n--
		buf[n] = 0
	}

	return n, nil
}

func getTermios(
	fd int,
) (unix.Termios, error) {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return unix.Termios{}, err
	}
	return *t, nil
}

func setTermios(
	fd int,
	t unix.Termios,
) error {
	return unix.IoctlSetTermios(fd, unix.TCSETS, &t)
}
