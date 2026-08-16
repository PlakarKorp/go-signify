package signify

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// memOpener serves files from a map, so these tests never touch the disk.
func memOpener(files map[string]string) Opener {
	return func(name string) (io.ReadCloser, error) {
		body, ok := files[name]
		if !ok {
			return nil, fmt.Errorf("no such file: %s", name)
		}

		return io.NopCloser(strings.NewReader(body)), nil
	}
}

func TestParseChecksumsTagged(t *testing.T) {
	list, err := ParseChecksums(fixture(t, "recipe.yaml.sum"))
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}

	if len(list) != 1 {
		t.Fatalf("got %d entries, want 1", len(list))
	}

	if list[0].Filename != "recipe.yaml" {
		t.Errorf("filename = %q", list[0].Filename)
	}

	if list[0].Algorithm != "SHA256" {
		t.Errorf("algorithm = %q", list[0].Algorithm)
	}
}

// GNU sha256sum's default output is accepted on input, so a list produced
// without --tag still works.
func TestParseChecksumsUntagged(t *testing.T) {
	list, err := ParseChecksums([]byte(
		"e285ed22e60232c37c2604d13c46e48af3c5e40044542fe5fe3b86b9f7e62c7f  s3.ptar\n"))
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}

	if len(list) != 1 || list[0].Filename != "s3.ptar" {
		t.Fatalf("got %+v", list)
	}
}

func TestParseChecksumsBinaryMarker(t *testing.T) {
	list, err := ParseChecksums([]byte(
		"e285ed22e60232c37c2604d13c46e48af3c5e40044542fe5fe3b86b9f7e62c7f *s3.ptar\n"))
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}

	if list[0].Filename != "s3.ptar" {
		t.Errorf("filename = %q, want s3.ptar", list[0].Filename)
	}
}

func TestParseChecksumsMultiple(t *testing.T) {
	in := "SHA256 (a.ptar) = " + strings.Repeat("a", 64) + "\n" +
		"\n" + // blank lines are skipped
		"SHA256 (b.ptar) = " + strings.Repeat("b", 64) + "\n"

	list, err := ParseChecksums([]byte(in))
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}

	if got := list.Filenames(); len(got) != 2 || got[0] != "a.ptar" || got[1] != "b.ptar" {
		t.Errorf("filenames = %v", got)
	}
}

// A malformed line must be an error: silently skipping it would let a
// corrupted list read as covering nothing.
func TestParseChecksumsRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"garbage\n",
		"SHA256 (x) = nothex\n",
		"SHA256 x = " + strings.Repeat("a", 64) + "\n",
		"= " + strings.Repeat("a", 64) + "\n",
	} {
		if _, err := ParseChecksums([]byte(in)); !errors.Is(err, ErrMalformedChecksum) {
			t.Errorf("ParseChecksums(%q) = %v, want ErrMalformedChecksum", in, err)
		}
	}
}

func TestChecksumFileAndVerify(t *testing.T) {
	body := "the artifact bytes"

	c, err := ChecksumFile("s3.ptar", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Verify(strings.NewReader(body)); err != nil {
		t.Errorf("Verify on matching content: %v", err)
	}

	if err := c.Verify(strings.NewReader("different")); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("got %v, want ErrDigestMismatch", err)
	}
}

func TestChecksumRoundTripThroughString(t *testing.T) {
	c, err := ChecksumFile("s3.ptar", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}

	list, err := ParseChecksums([]byte(c.String() + "\n"))
	if err != nil {
		t.Fatal(err)
	}

	if list[0] != c {
		t.Errorf("round trip changed the entry:\n got %+v\nwant %+v", list[0], c)
	}
}

func TestChecksumUnsupportedAlgorithm(t *testing.T) {
	c := Checksum{Algorithm: "MD5", Filename: "x", Digest: strings.Repeat("a", 32)}

	if err := c.Verify(strings.NewReader("x")); err == nil {
		t.Error("expected an error for an unsupported algorithm")
	}
}

func TestChecksumSHA512(t *testing.T) {
	// A SHA512 list must verify, since sha256(1) can emit one.
	list, err := ParseChecksums([]byte("SHA512 (x) = " + strings.Repeat("a", 128) + "\n"))
	if err != nil {
		t.Fatal(err)
	}

	if err := list[0].Verify(strings.NewReader("x")); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("expected a digest mismatch, got %v", err)
	}
}

func TestListFind(t *testing.T) {
	list, err := ParseChecksums(fixture(t, "recipe.yaml.sum"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := list.Find("recipe.yaml"); err != nil {
		t.Errorf("Find: %v", err)
	}

	if _, err := list.Find("absent"); !errors.Is(err, ErrNoChecksum) {
		t.Errorf("got %v, want ErrNoChecksum", err)
	}
}

// The published checksum list must verify against the live key and then check
// out against the published file: the whole signify -C flow, end to end.
func TestVerifyChecksumListAndCheckFiles(t *testing.T) {
	pk := distKey(t)

	sig, err := ParseSignature(fixture(t, "recipe.yaml.sum.sig"))
	if err != nil {
		t.Fatal(err)
	}

	list, err := VerifyChecksumList(pk, sig)
	if err != nil {
		t.Fatalf("VerifyChecksumList: %v", err)
	}

	if len(list) != 1 {
		t.Fatalf("got %d entries, want 1", len(list))
	}

	open := memOpener(map[string]string{
		"recipe.yaml": string(fixture(t, "recipe.yaml")),
	})

	if err := CheckFiles(pk, sig, open); err != nil {
		t.Errorf("CheckFiles on genuine content: %v", err)
	}
}

func TestCheckFilesRejectsTamperedContent(t *testing.T) {
	pk := distKey(t)

	sig, err := ParseSignature(fixture(t, "recipe.yaml.sum.sig"))
	if err != nil {
		t.Fatal(err)
	}

	open := memOpener(map[string]string{"recipe.yaml": "tampered"})

	if err := CheckFiles(pk, sig, open); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("got %v, want ErrDigestMismatch", err)
	}
}

// A signature from a key we did not ask about must not be accepted, even if
// the files themselves hash correctly.
func TestCheckFilesRejectsWrongKey(t *testing.T) {
	other, err := ParsePublicKey(fixture(t, "other.pub"))
	if err != nil {
		t.Fatal(err)
	}

	sig, err := ParseSignature(fixture(t, "recipe.yaml.sum.sig"))
	if err != nil {
		t.Fatal(err)
	}

	open := memOpener(map[string]string{
		"recipe.yaml": string(fixture(t, "recipe.yaml")),
	})

	if err := CheckFiles(other, sig, open); !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("got %v, want ErrKeyMismatch", err)
	}
}

func TestCheckFilesNamedSubset(t *testing.T) {
	_, sk := testKeyPair(t)

	a, _ := ChecksumFile("a.txt", strings.NewReader("aaa"))
	b, _ := ChecksumFile("b.txt", strings.NewReader("bbb"))

	list := ChecksumList{a, b}
	sig := sk.SignEmbedded([]byte(list.String()), "c")

	// Only b.txt is available; asking for it alone must succeed.
	open := memOpener(map[string]string{"b.txt": "bbb"})

	if err := CheckFiles(sk.Public(), sig, open, "b.txt"); err != nil {
		t.Errorf("CheckFiles(b.txt): %v", err)
	}

	// Asking for everything must fail, since a.txt cannot be opened.
	if err := CheckFiles(sk.Public(), sig, open); err == nil {
		t.Error("expected a failure for the missing file")
	}
}

func TestCheckFilesRejectsUnlistedName(t *testing.T) {
	_, sk := testKeyPair(t)

	c, _ := ChecksumFile("a.txt", strings.NewReader("aaa"))
	sig := sk.SignEmbedded([]byte(ChecksumList{c}.String()), "c")

	open := memOpener(map[string]string{"other.txt": "x"})

	if err := CheckFiles(sk.Public(), sig, open, "other.txt"); !errors.Is(err, ErrNoChecksum) {
		t.Errorf("got %v, want ErrNoChecksum", err)
	}
}

// A detached signature carries no list, so there is nothing to check against.
func TestVerifyChecksumListRejectsDetached(t *testing.T) {
	_, sk := testKeyPair(t)

	sig := sk.Sign([]byte("SHA256 (x) = ab\n"), "c")

	if _, err := VerifyChecksumList(sk.Public(), sig); !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("got %v, want ErrInvalidFormat", err)
	}
}

func TestChecksumListString(t *testing.T) {
	a, _ := ChecksumFile("a", bytes.NewReader(nil))

	if got := (ChecksumList{a}).String(); !strings.HasPrefix(got, "SHA256 (a) = ") {
		t.Errorf("String() = %q", got)
	}
}
