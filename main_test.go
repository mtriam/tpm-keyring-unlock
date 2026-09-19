package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestHandleRE(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "default handle",
			value: "0x81018043",
			want:  true,
		},
		{
			name:  "uppercase hex",
			value: "0x8101ABCD",
			want:  true,
		},
		{
			name:  "too short",
			value: "0x8101804",
			want:  false,
		},
		{
			name:  "too long",
			value: "0x810180430",
			want:  false,
		},
		{
			name:  "missing prefix",
			value: "81018043",
			want:  false,
		},
		{
			name:  "wrong prefix",
			value: "0X81018043",
			want:  false,
		},
		{
			name:  "non hexadecimal",
			value: "0x8101804g",
			want:  false,
		},
		{
			name:  "empty",
			value: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := handleRE.MatchString(tt.value)

			if got != tt.want {
				t.Fatalf(
					"handleRE.MatchString(%q) = %v, want %v",
					tt.value,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty",
			input: "",
			want:  "''",
		},
		{
			name:  "safe characters",
			input: "wheel",
			want:  "wheel",
		},
		{
			name:  "safe path",
			input: "user-name_01.txt",
			want:  "user-name_01.txt",
		},
		{
			name:  "space",
			input: "hello world",
			want:  "'hello world'",
		},
		{
			name:  "single quote",
			input: "it's",
			want:  "'it'\\''s'",
		},
		{
			name:  "shell metacharacters",
			input: "foo;rm -rf /",
			want:  "'foo;rm -rf /'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellQuote(tt.input)

			if got != tt.want {
				t.Fatalf(
					"shellQuote(%q) = %q, want %q",
					tt.input,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestValidatePCRSelection(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "default",
			value: "sha256:7",
			want:  true,
		},
		{
			name:  "multiple PCRs",
			value: "sha256:0,1,7",
			want:  true,
		},
		{
			name:  "multiple banks",
			value: "sha256:0,1+sha1:7",
			want:  true,
		},
		{
			name:  "case insensitive bank",
			value: "SHA256:7",
			want:  true,
		},
		{
			name:  "PCR zero",
			value: "sha256:0",
			want:  true,
		},
		{
			name:  "PCR 23",
			value: "sha256:23",
			want:  true,
		},
		{
			name:  "empty",
			value: "",
			want:  false,
		},
		{
			name:  "missing bank",
			value: ":7",
			want:  false,
		},
		{
			name:  "missing index",
			value: "sha256:",
			want:  false,
		},
		{
			name:  "invalid bank",
			value: "md5:7",
			want:  false,
		},
		{
			name:  "invalid index",
			value: "sha256:x",
			want:  false,
		},
		{
			name:  "PCR too high",
			value: "sha256:24",
			want:  false,
		},
		{
			name:  "negative PCR",
			value: "sha256:-1",
			want:  false,
		},
		{
			name:  "empty index",
			value: "sha256:7,",
			want:  false,
		},
		{
			name:  "empty bank",
			value: "sha256:7+",
			want:  false,
		},
		{
			name:  "wrong separator",
			value: "sha256:7;8",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePCRSelection(tt.value)

			if (err == nil) != tt.want {
				t.Fatalf(
					"validatePCRSelection(%q) error = %v, wantValid=%v",
					tt.value,
					err,
					tt.want,
				)
			}
		})
	}
}

func TestValidateDBusObjectPath(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "secret service collection",
			value: "/org/freedesktop/secrets/collection/login",
			want:  true,
		},
		{
			name:  "simple path",
			value: "/foo/bar",
			want:  true,
		},
		{
			name:  "underscore",
			value: "/foo/bar_01",
			want:  true,
		},
		{
			name:  "empty",
			value: "",
			want:  false,
		},
		{
			name:  "root",
			value: "/",
			want:  false,
		},
		{
			name:  "missing leading slash",
			value: "foo/bar",
			want:  false,
		},
		{
			name:  "double slash",
			value: "/foo//bar",
			want:  false,
		},
		{
			name:  "hyphen",
			value: "/foo/bar-baz",
			want:  false,
		},
		{
			name:  "space",
			value: "/foo/bar baz",
			want:  false,
		},
		{
			name:  "unicode",
			value: "/foo/żaba",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDBusObjectPath(tt.value)

			if (err == nil) != tt.want {
				t.Fatalf(
					"validateDBusObjectPath(%q) error = %v, wantValid=%v",
					tt.value,
					err,
					tt.want,
				)
			}
		})
	}
}

func TestValidateTPMName(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "sha256 TPM Name",
			value: "000b00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			want:  true,
		},
		{
			name:  "uppercase hex",
			value: "000B00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
			want:  true,
		},
		{
			name:  "empty",
			value: "",
			want:  false,
		},
		{
			name:  "odd length",
			value: "000b123",
			want:  false,
		},
		{
			name:  "too short",
			value: "000b",
			want:  false,
		},
		{
			name:  "non hexadecimal",
			value: "000bzzzz11223344",
			want:  false,
		},
		{
			name:  "sha256 digest too short",
			value: "000b00112233445566778899aabbccddeeff00112233445566778899aabbccddee",
			want:  false,
		},
		{
			name:  "unknown name algorithm",
			value: "000100112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTPMName(tt.value)

			if (err == nil) != tt.want {
				t.Fatalf(
					"validateTPMName(%q) error = %v, wantValid=%v",
					tt.value,
					err,
					tt.want,
				)
			}
		})
	}
}

func TestIsMissingCollectionError(t *testing.T) {
	missing := dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownObject"}
	noSuchObject := dbus.Error{Name: "org.freedesktop.Secret.Error.NoSuchObject"}
	other := dbus.Error{Name: "org.freedesktop.DBus.Error.AccessDenied"}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "unknown object", err: fmt.Errorf("wrapped: %w", missing), want: true},
		{name: "secret no such object", err: noSuchObject, want: true},
		{name: "access denied", err: other, want: false},
		{name: "ordinary error", err: errors.New("connection failed"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMissingCollectionError(tt.err); got != tt.want {
				t.Fatalf("isMissingCollectionError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestValidateMetadata(t *testing.T) {
	valid := metadata{
		Version:    metadataVersion,
		App:        appName,
		CreatedAt:  time.Date(2026, 9, 19, 8, 0, 0, 0, time.UTC),
		Collection: "/org/freedesktop/secrets/collection/login",
		PCRs:       "sha256:7",
		Handle:     "0x81018043",
		HandleName: "000b00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}

	if err := validateMetadata(valid); err != nil {
		t.Fatalf(
			"valid metadata rejected: %v",
			err,
		)
	}

	tests := []struct {
		name   string
		change func(*metadata)
	}{
		{
			name: "wrong version",
			change: func(md *metadata) {
				md.Version = metadataVersion - 1
			},
		},
		{
			name: "wrong app",
			change: func(md *metadata) {
				md.App = "other-app"
			},
		},
		{
			name: "missing created_at",
			change: func(md *metadata) {
				md.CreatedAt = time.Time{}
			},
		},
		{
			name: "invalid collection",
			change: func(md *metadata) {
				md.Collection = "not/a/dbus/path"
			},
		},
		{
			name: "invalid PCRs",
			change: func(md *metadata) {
				md.PCRs = "sha256:99"
			},
		},
		{
			name: "invalid handle",
			change: func(md *metadata) {
				md.Handle = "0x123"
			},
		},
		{
			name: "missing Name",
			change: func(md *metadata) {
				md.HandleName = ""
			},
		},
		{
			name: "invalid Name",
			change: func(md *metadata) {
				md.HandleName = "not-hex"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := valid
			tt.change(&md)

			if err := validateMetadata(md); err == nil {
				t.Fatalf(
					"invalid metadata was accepted: %+v",
					md,
				)
			}
		})
	}
}

func TestClassifyPersistentState(t *testing.T) {
	const name = "000b00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

	tests := []struct {
		name     string
		exists   bool
		wantName string
		gotName  string
		want     handleStatus
	}{
		{
			name:     "absent",
			exists:   false,
			wantName: name,
			gotName:  "",
			want:     handleAbsent,
		},
		{
			name:     "present without stored Name",
			exists:   true,
			wantName: "",
			gotName:  name,
			want:     handleUnverified,
		},
		{
			name:     "present but TPM Name unavailable",
			exists:   true,
			wantName: name,
			gotName:  "",
			want:     handleUnverified,
		},
		{
			name:     "our object",
			exists:   true,
			wantName: name,
			gotName:  name,
			want:     handleOurs,
		},
		{
			name:     "our object case insensitive",
			exists:   true,
			wantName: name,
			gotName:  "000B00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
			want:     handleOurs,
		},
		{
			name:     "foreign object",
			exists:   true,
			wantName: name,
			gotName:  "000c00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			want:     handleForeign,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyPersistentState(
				tt.exists,
				tt.wantName,
				tt.gotName,
			)

			if got != tt.want {
				t.Fatalf(
					"classifyPersistentState() = %v, want %v",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestWithRetryImmediateSuccess(t *testing.T) {
	calls := 0

	err := withRetry(
		time.Second,
		func() error {
			calls++
			return nil
		},
	)

	if err != nil {
		t.Fatalf(
			"withRetry returned error: %v",
			err,
		)
	}

	if calls != 1 {
		t.Fatalf(
			"function called %d times, want 1",
			calls,
		)
	}
}

func TestWithRetryRetriesUntilSuccess(t *testing.T) {
	calls := 0

	err := withRetry(
		retryInterval+200*time.Millisecond,
		func() error {
			calls++

			if calls < 2 {
				return errors.New("not ready")
			}

			return nil
		},
	)

	if err != nil {
		t.Fatalf(
			"withRetry returned error: %v",
			err,
		)
	}

	if calls != 2 {
		t.Fatalf(
			"function called %d times, want 2",
			calls,
		)
	}
}

func TestWithRetryNonPositiveTimeout(t *testing.T) {
	calls := 0

	wantErr := errors.New("expected")

	err := withRetry(
		0,
		func() error {
			calls++
			return wantErr
		},
	)

	if !errors.Is(err, wantErr) {
		t.Fatalf(
			"withRetry returned %v, want %v",
			err,
			wantErr,
		)
	}

	if calls != 1 {
		t.Fatalf(
			"function called %d times, want 1",
			calls,
		)
	}
}

func TestWithRetryTimeout(t *testing.T) {
	calls := 0

	wantErr := errors.New("still unavailable")

	start := time.Now()

	err := withRetry(
		100*time.Millisecond,
		func() error {
			calls++
			return wantErr
		},
	)

	elapsed := time.Since(start)

	if !errors.Is(err, wantErr) {
		t.Fatalf(
			"withRetry returned %v, want %v",
			err,
			wantErr,
		)
	}

	if calls != 1 {
		t.Fatalf(
			"function called %d times, want 1",
			calls,
		)
	}

	if elapsed > 200*time.Millisecond {
		t.Fatalf(
			"withRetry took too long: %v",
			elapsed,
		)
	}
}

func TestValidatePersistentHandle(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{
			name:  "default",
			value: "0x81018043",
			valid: true,
		},
		{
			name:  "lower_boundary",
			value: "0x81000000",
			valid: true,
		},
		{
			name:  "upper_boundary",
			value: "0x817fffff",
			valid: true,
		},
		{
			name:  "uppercase_hex",
			value: "0x817FFFFF",
			valid: true,
		},
		{
			name:  "platform_range_start",
			value: "0x81800000",
			valid: false,
		},
		{
			name:  "platform_range_end",
			value: "0x81ffffff",
			valid: false,
		},
		{
			name:  "below_owner_range",
			value: "0x80ffffff",
			valid: false,
		},
		{
			name:  "above_persistent_range",
			value: "0x82000000",
			valid: false,
		},
		{
			name:  "too_short",
			value: "0x8100000",
			valid: false,
		},
		{
			name:  "too_long",
			value: "0x810000000",
			valid: false,
		},
		{
			name:  "missing_prefix",
			value: "81018043",
			valid: false,
		},
		{
			name:  "wrong_prefix",
			value: "0X81018043",
			valid: false,
		},
		{
			name:  "non_hex",
			value: "0x81018xyz",
			valid: false,
		},
		{
			name:  "empty",
			value: "",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePersistentHandle(tt.value)

			if tt.valid && err != nil {
				t.Fatalf(
					"validatePersistentHandle(%q) error = %v, want valid",
					tt.value,
					err,
				)
			}

			if !tt.valid && err == nil {
				t.Fatalf(
					"validatePersistentHandle(%q) = nil, want error",
					tt.value,
				)
			}
		})
	}
}

func TestRejectSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")

	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := rejectSymlinkComponents(filepath.Join(link, "unit")); err == nil {
		t.Fatal("rejectSymlinkComponents accepted a symlink component")
	}

	plain := filepath.Join(root, "plain", "unit")
	if err := rejectSymlinkComponents(plain); err != nil {
		t.Fatalf("rejectSymlinkComponents rejected a path with missing components: %v", err)
	}
}

func TestStateMetadataRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	state := filepath.Join(root, "state")

	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	parentLinked := config{dir: filepath.Join(root, "link", "state")}
	parentLinked.refreshPaths()
	if err := checkExistingStatePermissions(parentLinked); err == nil {
		t.Fatal("checkExistingStatePermissions accepted a symlinked parent")
	}

	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	metadataTarget := filepath.Join(root, "metadata-target.json")
	if err := os.WriteFile(metadataTarget, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(metadataTarget, filepath.Join(state, "metadata.json")); err != nil {
		t.Fatal(err)
	}

	stateCfg := config{dir: state}
	stateCfg.refreshPaths()
	if _, err := readMetadata(stateCfg); err == nil {
		t.Fatal("readMetadata accepted a symlinked metadata file")
	}
}
