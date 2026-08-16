package signify

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// failingReader fails partway through, to exercise the io error paths that a
// well-behaved reader never reaches.
type failingReader struct{ err error }

func (r failingReader) Read(p []byte) (int, error) { return 0, r.err }

var errRead = errors.New("read failed")

func TestChecksumFilePropagatesReadError(t *testing.T) {
	if _, err := ChecksumFile("x", failingReader{errRead}); !errors.Is(err, errRead) {
		t.Errorf("got %v, want the reader's error", err)
	}
}

func TestChecksumVerifyPropagatesReadError(t *testing.T) {
	c, err := ChecksumFile("x", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Verify(failingReader{errRead}); !errors.Is(err, errRead) {
		t.Errorf("got %v, want the reader's error", err)
	}
}

func TestCheckFilesPropagatesOpenError(t *testing.T) {
	_, sk := testKeyPair(t)

	c, err := ChecksumFile("a.txt", strings.NewReader("aaa"))
	if err != nil {
		t.Fatal(err)
	}

	sig := sk.SignEmbedded([]byte(ChecksumList{c}.String()), "c")

	open := Opener(func(string) (io.ReadCloser, error) { return nil, errRead })

	if err := CheckFiles(sk.Public(), sig, open); !errors.Is(err, errRead) {
		t.Errorf("got %v, want the opener's error", err)
	}
}

func TestParseSignatureRejectsSecretKey(t *testing.T) {
	if _, err := ParseSignature(fixture(t, "testkey.sec")); !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("got %v, want ErrInvalidFormat", err)
	}
}

func TestParseSecretKeyRejectsWrongKDF(t *testing.T) {
	// A well-formed secret key whose KDF tag is not "BK".
	sk, err := ParseSecretKey(fixture(t, "testkey.sec"), []byte(fixturePassphrase))
	if err != nil {
		t.Fatal(err)
	}

	data, err := sk.Marshal([]byte(fixturePassphrase))
	if err != nil {
		t.Fatal(err)
	}

	corrupted := strings.Replace(string(data), "RWRCS", "RWRXX", 1)

	if _, err := ParseSecretKey([]byte(corrupted), []byte(fixturePassphrase)); err == nil {
		t.Error("expected an error for an unknown KDF")
	}
}

func TestParseFileRejectsCRLF(t *testing.T) {
	// Carriage returns must be tolerated rather than corrupt the payload.
	pk, err := ParsePublicKey(fixture(t, "testkey.pub"))
	if err != nil {
		t.Fatal(err)
	}

	data, err := pk.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	crlf := strings.ReplaceAll(string(data), "\n", "\r\n")

	got, err := ParsePublicKey([]byte(crlf))
	if err != nil {
		t.Fatalf("CRLF input rejected: %v", err)
	}

	if got.KeyNum != pk.KeyNum {
		t.Error("CRLF input parsed to a different key")
	}
}
