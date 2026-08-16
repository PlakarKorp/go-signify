package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// exec drives the CLI the way a shell would, with stdin supplying any
// passphrase.
func exec(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()

	var stdout, stderr bytes.Buffer

	err := run(args, strings.NewReader(stdin), &stdout, &stderr)

	return stdout.String(), stderr.String(), err
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	return path
}

func read(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

// generate makes a keypair in dir and returns the two paths.
func generate(t *testing.T, dir, name, passphrase string) (string, string) {
	t.Helper()

	pub := filepath.Join(dir, name+".pub")
	sec := filepath.Join(dir, name+".sec")

	args := []string{"-G", "-c", name, "-p", pub, "-s", sec}
	stdin := passphrase + "\n" + passphrase + "\n"

	if passphrase == "" {
		args = append(args, "-n")
		stdin = ""
	}

	if _, stderr, err := exec(t, stdin, args...); err != nil {
		t.Fatalf("-G: %v (%s)", err, stderr)
	}

	return pub, sec
}

func TestGenerateSignVerify(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "hunter2")

	msg := write(t, dir, "message.txt", "hello\n")

	if _, stderr, err := exec(t, "hunter2\n", "-S", "-s", sec, "-m", msg); err != nil {
		t.Fatalf("-S: %v (%s)", err, stderr)
	}

	stdout, stderr, err := exec(t, "", "-V", "-p", pub, "-m", msg)
	if err != nil {
		t.Fatalf("-V: %v (%s)", err, stderr)
	}

	if !strings.Contains(stdout, "Signature Verified") {
		t.Errorf("stdout = %q", stdout)
	}
}

// The secret key must not be world-readable. Windows does not implement Unix
// permission bits, so os.WriteFile's mode is not observable there.
func TestGenerateSecretKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permission bits on Windows")
	}

	dir := t.TempDir()

	_, sec := generate(t, dir, "k", "")

	fi, err := os.Stat(sec)
	if err != nil {
		t.Fatal(err)
	}

	if perm := fi.Mode().Perm(); perm&0077 != 0 {
		t.Errorf("secret key mode is %04o, want no group or other access", perm)
	}
}

func TestGenerateUnencrypted(t *testing.T) {
	dir := t.TempDir()

	_, sec := generate(t, dir, "k", "")

	msg := write(t, dir, "m.txt", "x\n")

	// No passphrase on stdin: an unencrypted key must not prompt.
	if _, stderr, err := exec(t, "", "-S", "-s", sec, "-m", msg); err != nil {
		t.Fatalf("-S with an unencrypted key: %v (%s)", err, stderr)
	}
}

func TestSignWrongPassphrase(t *testing.T) {
	dir := t.TempDir()

	_, sec := generate(t, dir, "k", "hunter2")
	msg := write(t, dir, "m.txt", "x\n")

	if _, _, err := exec(t, "wrong\n", "-S", "-s", sec, "-m", msg); err == nil {
		t.Error("expected -S to fail with a wrong passphrase")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "")
	msg := write(t, dir, "m.txt", "original\n")

	if _, _, err := exec(t, "", "-S", "-s", sec, "-m", msg); err != nil {
		t.Fatal(err)
	}

	write(t, dir, "m.txt", "tampered\n")

	if _, _, err := exec(t, "", "-V", "-p", pub, "-m", msg); err == nil {
		t.Error("expected -V to fail on a tampered message")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	dir := t.TempDir()

	_, sec := generate(t, dir, "a", "")
	otherPub, _ := generate(t, dir, "b", "")

	msg := write(t, dir, "m.txt", "x\n")

	if _, _, err := exec(t, "", "-S", "-s", sec, "-m", msg); err != nil {
		t.Fatal(err)
	}

	if _, _, err := exec(t, "", "-V", "-p", otherPub, "-m", msg); err == nil {
		t.Error("expected -V to fail against a different key")
	}
}

// -e round trip: the message is embedded on signing and extracted on verify.
func TestEmbeddedRoundTrip(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "")
	msg := write(t, dir, "m.txt", "embedded content\n")

	if _, _, err := exec(t, "", "-S", "-e", "-s", sec, "-m", msg); err != nil {
		t.Fatal(err)
	}

	sig := read(t, msg+".sig")
	if strings.Count(sig, "\n") != 3 {
		t.Errorf("embedded signature should have 3 lines, got %q", sig)
	}

	out := filepath.Join(dir, "extracted.txt")

	if _, _, err := exec(t, "", "-V", "-e", "-p", pub, "-x", msg+".sig", "-m", out); err != nil {
		t.Fatalf("-V -e: %v", err)
	}

	if got := read(t, out); got != "embedded content\n" {
		t.Errorf("extracted %q", got)
	}
}

func TestSigfileFlag(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "")
	msg := write(t, dir, "m.txt", "x\n")
	sig := filepath.Join(dir, "custom.sig")

	if _, _, err := exec(t, "", "-S", "-s", sec, "-m", msg, "-x", sig); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(sig); err != nil {
		t.Fatalf("-x did not write the signature: %v", err)
	}

	if _, _, err := exec(t, "", "-V", "-p", pub, "-m", msg, "-x", sig); err != nil {
		t.Errorf("-V with -x: %v", err)
	}
}

func TestQuietSuppressesOutput(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "")
	msg := write(t, dir, "m.txt", "x\n")

	if _, _, err := exec(t, "", "-S", "-s", sec, "-m", msg); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := exec(t, "", "-V", "-q", "-p", pub, "-m", msg)
	if err != nil {
		t.Fatal(err)
	}

	if stdout != "" {
		t.Errorf("-q produced output: %q", stdout)
	}
}

// -C: sign a checksum list, then check the listed files against it.
func TestCheckChecksumList(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "")

	write(t, dir, "a.txt", "aaa")
	write(t, dir, "b.txt", "bbb")

	sums := "SHA256 (a.txt) = 9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0\n" +
		"SHA256 (b.txt) = 3e744b9dc39389baf0c5a0660589b8402f3dbb49b89b3e75f2c9355852a3c677\n"

	sumfile := write(t, dir, "SHA256", sums)

	if _, _, err := exec(t, "", "-S", "-e", "-s", sec, "-m", sumfile); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := exec(t, "", "-C", "-p", pub, "-x", sumfile+".sig")
	if err != nil {
		t.Fatalf("-C: %v (%s)", err, stderr)
	}

	for _, want := range []string{"a.txt: OK", "b.txt: OK", "Signature Verified"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestCheckDetectsTamperedFile(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "")

	write(t, dir, "a.txt", "aaa")

	sums := "SHA256 (a.txt) = 9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0\n"
	sumfile := write(t, dir, "SHA256", sums)

	if _, _, err := exec(t, "", "-S", "-e", "-s", sec, "-m", sumfile); err != nil {
		t.Fatal(err)
	}

	write(t, dir, "a.txt", "tampered")

	if _, _, err := exec(t, "", "-C", "-p", pub, "-x", sumfile+".sig"); err == nil {
		t.Error("expected -C to fail on a tampered file")
	}
}

func TestCheckNamedSubset(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "")

	write(t, dir, "a.txt", "aaa")

	// b.txt is listed but absent: checking only a.txt must still succeed.
	sums := "SHA256 (a.txt) = 9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0\n" +
		"SHA256 (b.txt) = 3e744b9dc39389baf0c5a0660589b8402f3dbb49b89b3e75f2c9355852a3c677\n"

	sumfile := write(t, dir, "SHA256", sums)

	if _, _, err := exec(t, "", "-S", "-e", "-s", sec, "-m", sumfile); err != nil {
		t.Fatal(err)
	}

	if _, _, err := exec(t, "", "-C", "-p", pub, "-x", sumfile+".sig", "a.txt"); err != nil {
		t.Errorf("-C on a subset: %v", err)
	}

	if _, _, err := exec(t, "", "-C", "-p", pub, "-x", sumfile+".sig"); err == nil {
		t.Error("expected -C to fail when a listed file is missing")
	}
}

func TestModeSelection(t *testing.T) {
	cases := [][]string{
		{},                 // no mode
		{"-G", "-S"},       // two modes
		{"-V", "-C", "-G"}, // three
	}

	for _, args := range cases {
		if _, _, err := exec(t, "", args...); err == nil {
			t.Errorf("args %v: expected an error", args)
		}
	}
}

func TestMissingRequiredFlags(t *testing.T) {
	dir := t.TempDir()

	cases := [][]string{
		{"-G", "-p", filepath.Join(dir, "k.pub")}, // no -s
		{"-G", "-s", filepath.Join(dir, "k.sec")}, // no -p
		{"-S", "-m", "x"},                         // no -s
		{"-V", "-m", "x"},                         // no -p
		{"-C", "-p", "x"},                         // no -x
	}

	for _, args := range cases {
		if _, _, err := exec(t, "", args...); err == nil {
			t.Errorf("args %v: expected an error", args)
		}
	}
}

func TestVerifyMissingFiles(t *testing.T) {
	dir := t.TempDir()

	pub, _ := generate(t, dir, "k", "")

	if _, _, err := exec(t, "", "-V", "-p", pub, "-m", filepath.Join(dir, "absent")); err == nil {
		t.Error("expected an error for a missing message")
	}

	if _, _, err := exec(t, "", "-V", "-p", filepath.Join(dir, "absent.pub"),
		"-m", pub); err == nil {
		t.Error("expected an error for a missing public key")
	}
}

func TestFlagParseError(t *testing.T) {
	if _, _, err := exec(t, "", "-nosuchflag"); err == nil {
		t.Error("expected an error for an unknown flag")
	}
}

func TestEmptyPassphraseRejected(t *testing.T) {
	dir := t.TempDir()

	pub := filepath.Join(dir, "k.pub")
	sec := filepath.Join(dir, "k.sec")

	if _, _, err := exec(t, "\n", "-G", "-p", pub, "-s", sec); err == nil {
		t.Error("expected an empty passphrase to be rejected")
	}
}

func TestPassphraseMismatchRejected(t *testing.T) {
	dir := t.TempDir()

	pub := filepath.Join(dir, "k.pub")
	sec := filepath.Join(dir, "k.sec")

	if _, _, err := exec(t, "one\ntwo\n", "-G", "-p", pub, "-s", sec); err == nil {
		t.Error("expected mismatched passphrases to be rejected")
	}
}

// EOF on stdin must be an error, not an empty passphrase silently accepted.
func TestPassphraseEOF(t *testing.T) {
	dir := t.TempDir()

	if _, _, err := exec(t, "", "-G",
		"-p", filepath.Join(dir, "k.pub"),
		"-s", filepath.Join(dir, "k.sec")); err == nil {
		t.Error("expected EOF on stdin to be an error")
	}
}

func TestSignMissingFiles(t *testing.T) {
	dir := t.TempDir()

	_, sec := generate(t, dir, "k", "")

	// Missing secret key.
	if _, _, err := exec(t, "", "-S", "-s", filepath.Join(dir, "absent.sec"),
		"-m", filepath.Join(dir, "m.txt")); err == nil {
		t.Error("expected an error for a missing secret key")
	}

	// Missing message.
	if _, _, err := exec(t, "", "-S", "-s", sec,
		"-m", filepath.Join(dir, "absent.txt")); err == nil {
		t.Error("expected an error for a missing message")
	}
}

func TestSignUnwritableSigfile(t *testing.T) {
	dir := t.TempDir()

	_, sec := generate(t, dir, "k", "")
	msg := write(t, dir, "m.txt", "x\n")

	// A signature path inside a nonexistent directory cannot be written.
	sig := filepath.Join(dir, "no-such-dir", "out.sig")

	if _, _, err := exec(t, "", "-S", "-s", sec, "-m", msg, "-x", sig); err == nil {
		t.Error("expected an error writing to a nonexistent directory")
	}
}

func TestGenerateUnwritableOutput(t *testing.T) {
	dir := t.TempDir()

	if _, _, err := exec(t, "", "-G", "-n",
		"-p", filepath.Join(dir, "k.pub"),
		"-s", filepath.Join(dir, "no-such-dir", "k.sec")); err == nil {
		t.Error("expected an error writing the secret key")
	}

	if _, _, err := exec(t, "", "-G", "-n",
		"-p", filepath.Join(dir, "no-such-dir", "k.pub"),
		"-s", filepath.Join(dir, "k2.sec")); err == nil {
		t.Error("expected an error writing the public key")
	}
}

func TestVerifyMalformedFiles(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "")
	msg := write(t, dir, "m.txt", "x\n")

	if _, _, err := exec(t, "", "-S", "-s", sec, "-m", msg); err != nil {
		t.Fatal(err)
	}

	// A corrupt public key.
	bad := write(t, dir, "bad.pub", "not a signify file\n")
	if _, _, err := exec(t, "", "-V", "-p", bad, "-m", msg); err == nil {
		t.Error("expected an error for a malformed public key")
	}

	// A corrupt signature.
	badsig := write(t, dir, "bad.sig", "not a signify file\n")
	if _, _, err := exec(t, "", "-V", "-p", pub, "-m", msg, "-x", badsig); err == nil {
		t.Error("expected an error for a malformed signature")
	}

	// A missing signature.
	if _, _, err := exec(t, "", "-V", "-p", pub, "-m", msg,
		"-x", filepath.Join(dir, "absent.sig")); err == nil {
		t.Error("expected an error for a missing signature")
	}
}

func TestVerifyEmbeddedUnwritableOutput(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "")
	msg := write(t, dir, "m.txt", "x\n")

	if _, _, err := exec(t, "", "-S", "-e", "-s", sec, "-m", msg); err != nil {
		t.Fatal(err)
	}

	if _, _, err := exec(t, "", "-V", "-e", "-p", pub, "-x", msg+".sig",
		"-m", filepath.Join(dir, "no-such-dir", "out.txt")); err == nil {
		t.Error("expected an error writing the extracted message")
	}
}

func TestCheckMalformedFiles(t *testing.T) {
	dir := t.TempDir()

	pub, sec := generate(t, dir, "k", "")

	write(t, dir, "a.txt", "aaa")
	sums := "SHA256 (a.txt) = 9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0\n"
	sumfile := write(t, dir, "SHA256", sums)

	if _, _, err := exec(t, "", "-S", "-e", "-s", sec, "-m", sumfile); err != nil {
		t.Fatal(err)
	}

	// Missing signature file.
	if _, _, err := exec(t, "", "-C", "-p", pub,
		"-x", filepath.Join(dir, "absent.sig")); err == nil {
		t.Error("expected an error for a missing signature")
	}

	// Malformed signature file.
	bad := write(t, dir, "bad.sig", "garbage\n")
	if _, _, err := exec(t, "", "-C", "-p", pub, "-x", bad); err == nil {
		t.Error("expected an error for a malformed signature")
	}

	// Malformed public key.
	badpub := write(t, dir, "bad.pub", "garbage\n")
	if _, _, err := exec(t, "", "-C", "-p", badpub, "-x", sumfile+".sig"); err == nil {
		t.Error("expected an error for a malformed public key")
	}
}

// A secret key that is neither valid nor merely passphrase-protected must be
// reported as malformed rather than treated as encrypted.
func TestSignMalformedSecretKey(t *testing.T) {
	dir := t.TempDir()

	bad := write(t, dir, "bad.sec", "garbage\n")
	msg := write(t, dir, "m.txt", "x\n")

	if _, _, err := exec(t, "", "-S", "-s", bad, "-m", msg); err == nil {
		t.Error("expected an error for a malformed secret key")
	}
}

func TestVersionFlag(t *testing.T) {
	stdout, _, err := exec(t, "", "-version")
	if err != nil {
		t.Fatalf("-version: %v", err)
	}

	if !strings.HasPrefix(stdout, "signify v") {
		t.Errorf("stdout = %q, want a leading \"signify v\"", stdout)
	}

	// -version stands alone: it must not require a mode, and must not be
	// refused for combining with one.
	if _, _, err := exec(t, "", "-version", "-G"); err != nil {
		t.Errorf("-version alongside a mode: %v", err)
	}
}
