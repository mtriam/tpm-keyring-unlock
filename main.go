package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/godbus/dbus/v5"
)

const (
	appName        = "tpm-keyring-unlock"
	serviceName    = "tpm-keyring-unlock.service"
	collectionPath = "/org/freedesktop/secrets/collection/Default_5fkeyring"
	retryTimeout   = 30 * time.Second
	retryInterval  = 500 * time.Millisecond
)

type config struct {
	dir         string
	pcrs        string
	collection  string
	timeout     time.Duration
	installPath string
	systemdPath string
	sealedPub   string
	sealedPriv  string
	secretHash  string
	metadata    string
}

type metadata struct {
	Version      int       `json:"version"`
	App          string    `json:"app"`
	CreatedAt    time.Time `json:"created_at"`
	Collection   string    `json:"collection"`
	PCRs         string    `json:"pcrs"`
	SecretSHA256 string    `json:"secret_sha256"`
}

type secretValue struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, colorize("error:", colorRed), err)
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
	if args[1] == "-h" || args[1] == "--help" || args[1] == "help" {
		usage()
		return nil
	}

	fs := flag.NewFlagSet(args[1], flag.ContinueOnError)
	fs.StringVar(&cfg.dir, "state-dir", cfg.dir, "state directory")
	fs.StringVar(&cfg.pcrs, "pcrs", cfg.pcrs, "PCR selection")
	fs.StringVar(&cfg.collection, "collection", cfg.collection, "Secret Service collection object path")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "DBus retry timeout")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	cfg.refreshPaths()

	switch args[1] {
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
		usage()
		return fmt.Errorf("unknown command %q", args[1])
	}
}

func usage() {
	fmt.Printf(`%s: TPM2 sealed GNOME keyring unlock helper

Usage:
  %[1]s enroll    [-pcrs sha256:7] [-timeout 30s]
  %[1]s unlock    [-timeout 30s]
  %[1]s status
  %[1]s install
  %[1]s uninstall
  %[1]s purge
  %[1]s doctor

`, colorize(appName, colorBold))
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
		collection:  collectionPath,
		timeout:     retryTimeout,
		installPath: exe,
		systemdPath: filepath.Join(home, ".config", "systemd", "user", serviceName),
	}
	cfg.refreshPaths()
	return cfg, nil
}

func (c *config) refreshPaths() {
	c.sealedPub = filepath.Join(c.dir, "keyring.pub")
	c.sealedPriv = filepath.Join(c.dir, "keyring.priv")
	c.secretHash = filepath.Join(c.dir, "secret.sha256")
	c.metadata = filepath.Join(c.dir, "metadata.json")
}

func enroll(cfg config) error {
	if err := requireCommands("tpm2_createprimary", "tpm2_create"); err != nil {
		return err
	}
	if err := checkTPMReady(); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(cfg.dir, 0700); err != nil {
		return err
	}

	fmt.Print("GNOME keyring master password: ")
	secret, err := readPassword()
	if err != nil {
		return err
	}
	defer zero(secret)
	fmt.Println()
	if len(secret) == 0 {
		return errors.New("empty keyring password refused")
	}

	fmt.Println(colorize("verifying password against the real default collection...", colorDim))
	if err := unlockCollection(cfg.collection, secret); err != nil {
		return fmt.Errorf("password did not unlock collection: %w", err)
	}

	tmp, err := os.MkdirTemp("", appName+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	primaryCtx := filepath.Join(tmp, "primary.ctx")
	if err := runCmd(nil, "tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", primaryCtx); err != nil {
		return err
	}
	if err := runCmd(bytes.NewReader(secret), "tpm2_create", "-C", primaryCtx, "-u", cfg.sealedPub, "-r", cfg.sealedPriv, "-i", "-", "-l", cfg.pcrs); err != nil {
		return err
	}
	sum := sha256.Sum256(secret)
	secretHash := hex.EncodeToString(sum[:])
	if err := os.WriteFile(cfg.secretHash, []byte(secretHash+"\n"), 0600); err != nil {
		return err
	}
	_ = os.Chmod(cfg.sealedPub, 0600)
	_ = os.Chmod(cfg.sealedPriv, 0600)
	if err := writeMetadata(cfg, secretHash); err != nil {
		return err
	}
	if err := checkStatePermissions(cfg); err != nil {
		return err
	}
	fmt.Println(colorize("self-testing sealed secret...", colorDim))
	selfTestSecret, err := unsealSecret(cfg)
	if err != nil {
		cleanupEnrollment(cfg)
		return fmt.Errorf("enroll self-test failed: %w", err)
	}
	defer zero(selfTestSecret)
	if !bytes.Equal(selfTestSecret, secret) {
		cleanupEnrollment(cfg)
		return errors.New("enroll self-test failed: unsealed secret mismatch")
	}
	fmt.Println(colorize("enrolled sealed secret in", colorGreen), cfg.dir)
	return nil
}

func unlock(cfg config) error {
	if err := requireCommands("tpm2_createprimary", "tpm2_load", "tpm2_unseal"); err != nil {
		return err
	}
	if missingAny(cfg.sealedPub, cfg.sealedPriv) {
		return errors.New("not enrolled; run enroll first")
	}

	locked, err := collectionLockedWithRetry(cfg.collection, cfg.timeout)
	if err != nil {
		return err
	}
	if !locked {
		fmt.Println(colorize("collection already unlocked", colorGreen))
		return nil
	}

	if err := checkStatePermissions(cfg); err != nil {
		return err
	}
	secret, err := unsealSecret(cfg)
	if err != nil {
		return err
	}
	defer zero(secret)
	if err := verifyHash(cfg, secret); err != nil {
		return err
	}
	if err := unlockCollectionWithRetry(cfg.collection, secret, cfg.timeout); err != nil {
		return err
	}
	locked, err = collectionLockedWithRetry(cfg.collection, cfg.timeout)
	if err != nil {
		return err
	}
	if locked {
		return errors.New("unlock method returned success but collection remains locked")
	}
	fmt.Println(colorize("collection unlocked", colorGreen))
	return nil
}

func status(cfg config) error {
	fmt.Println("state dir:", cfg.dir)
	fmt.Println("collection:", cfg.collection)
	fmt.Println("pcrs:", cfg.pcrs)
	fmt.Println("enrolled:", !missingAny(cfg.sealedPub, cfg.sealedPriv))
	if md, err := readMetadata(cfg); err == nil {
		fmt.Println("metadata pcrs:", md.PCRs)
		fmt.Println("metadata collection:", md.Collection)
		fmt.Println("metadata created:", md.CreatedAt.Format(time.RFC3339))
	} else {
		fmt.Println("metadata: unavailable:", err)
	}
	printStatePermissionsCheck(cfg)
	locked, err := collectionLocked(cfg.collection)
	if err != nil {
		fmt.Println("collection locked: unknown:", err)
	} else {
		fmt.Println("collection locked:", locked)
	}
	_, err = os.Stat(cfg.systemdPath)
	fmt.Println("systemd user service installed:", err == nil)
	return nil
}

func install(cfg config) error {
	if err := os.MkdirAll(filepath.Dir(cfg.systemdPath), 0755); err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=Unlock GNOME keyring default collection using TPM2 sealed secret

[Service]
Type=oneshot
ExecStart=%s unlock

[Install]
WantedBy=default.target
`, quoteSystemdArg(cfg.installPath))
	if err := os.WriteFile(cfg.systemdPath, []byte(unit), 0644); err != nil {
		return err
	}
	fmt.Println(colorize("installed", colorGreen), cfg.systemdPath)
	_ = runCmd(nil, "systemctl", "--user", "daemon-reload")
	_ = runCmd(nil, "systemctl", "--user", "enable", serviceName)
	return nil
}

func uninstall(cfg config) error {
	_ = runCmd(nil, "systemctl", "--user", "stop", serviceName)
	_ = runCmd(nil, "systemctl", "--user", "disable", serviceName)
	if err := os.Remove(cfg.systemdPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = runCmd(nil, "systemctl", "--user", "daemon-reload")
	fmt.Println(colorize("uninstalled", colorGreen), cfg.systemdPath)
	return nil
}

func purge(cfg config) error {
	if err := removeEnrollment(cfg); err != nil {
		return err
	}
	fmt.Println(colorize("purged sealed state from", colorYellow), cfg.dir)
	return nil
}

func cleanupEnrollment(cfg config) {
	_ = removeEnrollment(cfg)
}

func removeEnrollment(cfg config) error {
	for _, path := range []string{cfg.sealedPub, cfg.sealedPriv, cfg.secretHash, cfg.metadata} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func doctor(cfg config) error {
	fmt.Println(colorize("Tooling", colorBold))
	for _, c := range []string{"tpm2_getcap", "tpm2_pcrread", "tpm2_createprimary", "tpm2_create", "tpm2_load", "tpm2_unseal", "systemctl"} {
		_, err := exec.LookPath(c)
		printBool(c, err == nil)
	}
	fmt.Println()
	fmt.Println(colorize("TPM", colorBold))
	if line, err := tpmDeviceSummary(); err == nil {
		fmt.Println(line)
	} else {
		fmt.Println("/dev/tpmrm0          " + colorize("missing", colorRed) + ": " + err.Error())
	}
	if out, err := exec.Command("id").Output(); err == nil {
		fmt.Print(strings.TrimSpace(string(out)), "\n")
	}
	printCheck("tpm properties", runDiagnosticCmd("tpm2_getcap", "properties-fixed"))
	printCheck("tpm pcr7", runDiagnosticCmd("tpm2_pcrread", cfg.pcrs))
	printTPMPermissionAdvice()
	fmt.Println()
	fmt.Println(colorize("DBus", colorBold))
	printCheck("session bus", checkSessionBus())
	printCheck("secret service", checkSecretServiceName())
	if locked, err := collectionLocked(cfg.collection); err != nil {
		printCheck("collection locked property", err)
	} else {
		fmt.Printf("%-24s %s locked=%v\n", "collection locked property", colorize("ok", colorGreen), locked)
	}
	fmt.Println()
	fmt.Println(colorize("State", colorBold))
	printStatePermissionsCheck(cfg)
	return nil
}

func verifyHash(cfg config, secret []byte) error {
	wantBytes, err := os.ReadFile(cfg.secretHash)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(secret)
	got := hex.EncodeToString(sum[:])
	want := strings.TrimSpace(string(wantBytes))
	if want != "" && got != want {
		return errors.New("unsealed secret hash mismatch")
	}
	return nil
}

func unsealSecret(cfg config) ([]byte, error) {
	tmp, err := os.MkdirTemp("", appName+"-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	primaryCtx := filepath.Join(tmp, "primary.ctx")
	keyCtx := filepath.Join(tmp, "key.ctx")
	if err := runCmd(nil, "tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", primaryCtx); err != nil {
		return nil, err
	}
	if err := runCmd(nil, "tpm2_load", "-C", primaryCtx, "-u", cfg.sealedPub, "-r", cfg.sealedPriv, "-c", keyCtx); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := runCmdOut(&out, nil, "tpm2_unseal", "-c", keyCtx); err != nil {
		return nil, err
	}
	secret := append([]byte(nil), out.Bytes()...)
	return secret, nil
}

func writeMetadata(cfg config, secretHash string) error {
	md := metadata{
		Version:      1,
		App:          appName,
		CreatedAt:    time.Now().UTC(),
		Collection:   cfg.collection,
		PCRs:         cfg.pcrs,
		SecretSHA256: secretHash,
	}
	data, err := json.MarshalIndent(md, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(cfg.metadata, data, 0600); err != nil {
		return err
	}
	return os.Chmod(cfg.metadata, 0600)
}

func readMetadata(cfg config) (metadata, error) {
	var md metadata
	data, err := os.ReadFile(cfg.metadata)
	if err != nil {
		return md, err
	}
	if err := json.Unmarshal(data, &md); err != nil {
		return md, err
	}
	return md, nil
}

func checkStatePermissions(cfg config) error {
	if err := checkPathPerm(cfg.dir, 0700); err != nil {
		return err
	}
	for _, path := range []string{cfg.sealedPub, cfg.sealedPriv, cfg.secretHash, cfg.metadata} {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := checkPathPerm(path, 0600); err != nil {
			return err
		}
	}
	return nil
}

func checkPathPerm(path string, want os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	got := info.Mode().Perm()
	if got != want {
		return fmt.Errorf("%s has permissions %04o, want %04o", path, got, want)
	}
	return nil
}

func unlockCollection(collection string, secret []byte) error {
	conn, err := dbus.SessionBus()
	if err != nil {
		return err
	}
	defer conn.Close()

	obj := conn.Object("org.freedesktop.secrets", dbus.ObjectPath("/org/freedesktop/secrets"))
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := obj.Call(
		"org.freedesktop.Secret.Service.OpenSession",
		0,
		"plain",
		dbus.MakeVariant(""),
	).Store(&output, &session); err != nil {
		return fmt.Errorf("OpenSession failed: %w", err)
	}

	dbusSecret := secretValue{
		Session:     session,
		Parameters:  []byte{},
		Value:       secret,
		ContentType: "text/plain",
	}
	if err := obj.Call(
		"org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.UnlockWithMasterPassword",
		0,
		dbus.ObjectPath(collection),
		dbusSecret,
	).Err; err != nil {
		return fmt.Errorf("UnlockWithMasterPassword failed: %w", err)
	}
	return nil
}

func unlockCollectionWithRetry(collection string, secret []byte, timeout time.Duration) error {
	return withRetry(timeout, func() error {
		return unlockCollection(collection, secret)
	})
}

func collectionLocked(collection string) (bool, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return false, err
	}
	defer conn.Close()

	obj := conn.Object("org.freedesktop.secrets", dbus.ObjectPath(collection))
	var lockedVariant dbus.Variant
	if err := obj.Call(
		"org.freedesktop.DBus.Properties.Get",
		0,
		"org.freedesktop.Secret.Collection",
		"Locked",
	).Store(&lockedVariant); err != nil {
		return false, fmt.Errorf("Properties.Get Locked failed: %w", err)
	}
	locked, ok := lockedVariant.Value().(bool)
	if !ok {
		return false, fmt.Errorf("Properties.Get Locked returned %T, want bool", lockedVariant.Value())
	}
	return locked, nil
}

func collectionLockedWithRetry(collection string, timeout time.Duration) (bool, error) {
	var locked bool
	err := withRetry(timeout, func() error {
		var err error
		locked, err = collectionLocked(collection)
		return err
	})
	return locked, err
}

func withRetry(timeout time.Duration, fn func() error) error {
	if timeout <= 0 {
		return fn()
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().Add(retryInterval).After(deadline) {
			return lastErr
		}
		time.Sleep(retryInterval)
	}
}

func checkSessionBus() error {
	conn, err := dbus.SessionBus()
	if err != nil {
		return err
	}
	return conn.Close()
}

func checkSecretServiceName() error {
	conn, err := dbus.SessionBus()
	if err != nil {
		return err
	}
	defer conn.Close()
	var owner string
	obj := conn.Object("org.freedesktop.DBus", dbus.ObjectPath("/org/freedesktop/DBus"))
	if err := obj.Call("org.freedesktop.DBus.GetNameOwner", 0, "org.freedesktop.secrets").Store(&owner); err != nil {
		return err
	}
	if owner == "" {
		return errors.New("org.freedesktop.secrets has no owner")
	}
	return nil
}

func checkTPMReady() error {
	if err := runDiagnosticCmd("tpm2_getcap", "properties-fixed"); err != nil {
		if advice, ok := tpmPermissionAdvice(); ok {
			return fmt.Errorf("%w\n\n%s", err, advice)
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
	info, err := os.Stat("/dev/tpmrm0")
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Sprintf("/dev/tpmrm0          mode=%s", info.Mode()), nil
	}
	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	gid := strconv.FormatUint(uint64(stat.Gid), 10)
	owner := fallback(lookupUsername(uid), uid)
	group := fallback(lookupGroupName(gid), gid)
	return fmt.Sprintf("/dev/tpmrm0          mode=%s owner=%s(%s) group=%s(%s)", info.Mode(), owner, uid, group, gid), nil
}

func tpmPermissionAdvice() (string, bool) {
	info, err := os.Stat("/dev/tpmrm0")
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

	deviceUID := strconv.FormatUint(uint64(stat.Uid), 10)
	deviceGID := strconv.FormatUint(uint64(stat.Gid), 10)
	ownerName := lookupUsername(deviceUID)
	groupName := lookupGroupName(deviceGID)
	groupForCommand := groupName
	if groupForCommand == "" {
		groupForCommand = deviceGID
	}

	current, err := user.Current()
	if err != nil {
		return "", false
	}
	groupIDs, err := current.GroupIds()
	if err != nil {
		return "", false
	}
	if stringInSlice(deviceGID, groupIDs) {
		return "", false
	}
	username := current.Username
	if username == "" {
		username = "$USER"
	}

	var b strings.Builder
	fmt.Fprintln(&b, colorize("TPM permission hint:", colorYellow))
	fmt.Fprintf(&b, "  /dev/tpmrm0 owner: %s (%s)\n", fallback(ownerName, deviceUID), deviceUID)
	fmt.Fprintf(&b, "  /dev/tpmrm0 group: %s (%s)\n", fallback(groupName, deviceGID), deviceGID)
	fmt.Fprintf(&b, "  /dev/tpmrm0 mode:  %s\n", info.Mode())
	fmt.Fprintf(&b, "  your groups:       %s\n", userGroupSummary(groupIDs))
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "The TPM resource manager is group-writable, but your user is not in that group.")
	fmt.Fprintln(&b, colorize("Run this exact command:", colorYellow))
	fmt.Fprintf(&b, "  %s\n", colorize(fmt.Sprintf("sudo usermod -aG %s %s", shellQuote(groupForCommand), shellQuote(username)), colorCyan))
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Use the device group shown above (%s), not your hostname or username.\n", groupForCommand)
	fmt.Fprintln(&b, "Then fully log out of the graphical session and log back in, or reboot.")
	fmt.Fprintln(&b, "Starting a new shell with 'exec fish' (or any shell) is not enough for group membership changes.")
	return strings.TrimRight(b.String(), "\n"), true
}

func lookupUsername(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return ""
	}
	return u.Username
}

func lookupGroupName(gid string) string {
	g, err := user.LookupGroupId(gid)
	if err != nil {
		return ""
	}
	return g.Name
}

func userGroupSummary(groupIDs []string) string {
	if len(groupIDs) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(groupIDs))
	for _, gid := range groupIDs {
		name := lookupGroupName(gid)
		if name == "" {
			parts = append(parts, gid)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", name, gid))
	}
	return strings.Join(parts, ", ")
}

func stringInSlice(needle string, haystack []string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func fallback(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func printCheck(name string, err error) {
	if err != nil {
		fmt.Printf("%-24s %s: %v\n", name, colorize("fail", colorRed), err)
		return
	}
	fmt.Printf("%-24s %s\n", name, colorize("ok", colorGreen))
}

func printBool(name string, ok bool) {
	value := colorize("true", colorGreen)
	if !ok {
		value = colorize("false", colorRed)
	}
	fmt.Printf("%-20s %s\n", name, value)
}

func printStatePermissionsCheck(cfg config) {
	if _, err := os.Stat(cfg.dir); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("%-24s %s %s\n", "state permissions", colorize("ok", colorGreen), colorize("(not enrolled yet)", colorDim))
		return
	}
	printCheck("state permissions", checkStatePermissions(cfg))
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

func colorize(s, color string) string {
	if !colorsEnabled() {
		return s
	}
	return color + s + colorReset
}

func colorsEnabled() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func quoteSystemdArg(arg string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(arg)
	return `"` + escaped + `"`
}

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if strings.IndexFunc(arg, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.')
	}) == -1 {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

func runCmd(stdin io.Reader, name string, args ...string) error {
	return runCmdOut(io.Discard, stdin, name, args...)
}

func runCmdOut(stdout io.Writer, stdin io.Reader, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func runDiagnosticCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := firstNonEmptyLine(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s failed: %s", name, msg)
	}
	return nil
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func requireCommands(names ...string) error {
	var missing []string
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing commands: %s", strings.Join(missing, ", "))
	}
	return nil
}

func missingAny(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return true
		}
	}
	return false
}

func readPassword() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	oldState, err := getTermios(fd)
	if err != nil {
		reader := bufio.NewReader(os.Stdin)
		return reader.ReadBytes('\n')
	}
	newState := oldState
	newState.Lflag &^= syscall.ECHO
	if err := setTermios(fd, newState); err != nil {
		return nil, err
	}
	defer setTermios(fd, oldState)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

func getTermios(fd int) (syscall.Termios, error) {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return t, errno
	}
	return t, nil
}

func setTermios(fd int, t syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return errno
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
