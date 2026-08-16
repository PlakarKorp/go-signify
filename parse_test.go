package signify

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// Every parser shares parseFile, so each must forward its errors rather than
// mask them behind a size check.
func TestParsersForwardEnvelopeErrors(t *testing.T) {
	cases := []struct {
		name string
		data string
		want error
	}{
		{"empty", "", ErrInvalidFormat},
		{"no header", "nope\nRWQ=\n", ErrInvalidFormat},
		{"bad base64", commentHdr + "c\n!!!!\n", ErrInvalidFormat},
		{"short payload", commentHdr + "c\nRQ==\n", ErrInvalidFormat},
		{"wrong algorithm", commentHdr + "c\nWFgAAAAAAAAAAA==\n", ErrUnsupportedAlgorithm},
		{"long comment", commentHdr + strings.Repeat("x", MaxCommentLen) + "\nRWQ=\n", ErrCommentTooLong},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePublicKey([]byte(tc.data)); !errors.Is(err, tc.want) {
				t.Errorf("ParsePublicKey: got %v, want %v", err, tc.want)
			}

			if _, err := ParseSignature([]byte(tc.data)); !errors.Is(err, tc.want) {
				t.Errorf("ParseSignature: got %v, want %v", err, tc.want)
			}

			if _, err := ParseSecretKey([]byte(tc.data), nil); !errors.Is(err, tc.want) {
				t.Errorf("ParseSecretKey: got %v, want %v", err, tc.want)
			}
		})
	}
}

// A payload of exactly one byte exercises the length guard before the
// algorithm tag is read, which a two-byte payload would skip.
func TestParseFileRejectsOneBytePayload(t *testing.T) {
	if _, err := ParsePublicKey([]byte(commentHdr + "c\nRQ==\n")); !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("got %v, want ErrInvalidFormat", err)
	}
}

// Each type must reject the other two, since they differ only by payload
// length once the envelope has been parsed.
func TestParsersRejectEachOthersFiles(t *testing.T) {
	pub := fixture(t, "testkey.pub")
	sec := fixture(t, "testkey.sec")
	sig := fixture(t, "recipe.yaml.sum.sig")

	for _, tc := range []struct {
		name  string
		parse func([]byte) error
		data  [][]byte
	}{
		{"ParsePublicKey", func(b []byte) error { _, err := ParsePublicKey(b); return err },
			[][]byte{sec, sig}},
		{"ParseSignature", func(b []byte) error { _, err := ParseSignature(b); return err },
			[][]byte{pub, sec}},
		{"ParseSecretKey", func(b []byte) error { _, err := ParseSecretKey(b, nil); return err },
			[][]byte{pub, sig}},
	} {
		for _, data := range tc.data {
			if err := tc.parse(data); !errors.Is(err, ErrInvalidFormat) {
				t.Errorf("%s: got %v, want ErrInvalidFormat", tc.name, err)
			}
		}
	}
}

// A failing or exhausted entropy source must surface as an error rather than
// a key built from whatever bytes were available.
func TestGenerateKeyFromFailingEntropy(t *testing.T) {
	// ed25519 takes 32 bytes, the key number 8, the salt 16.
	for _, n := range []int{0, 10, 34, 50} {
		if _, _, err := GenerateKeyFrom(&truncatedReader{limit: n}, "c"); err == nil {
			t.Errorf("entropy limited to %d bytes: expected an error", n)
		}
	}

	// With enough entropy it must succeed, so the limits above are testing
	// the failure paths rather than a broken reader.
	if _, _, err := GenerateKeyFrom(&truncatedReader{limit: 1 << 12}, "c"); err != nil {
		t.Errorf("with ample entropy: %v", err)
	}
}

// truncatedReader yields zero bytes until limit, then fails.
type truncatedReader struct {
	limit int
	read  int
}

func (r *truncatedReader) Read(p []byte) (int, error) {
	if r.read >= r.limit {
		return 0, io.ErrUnexpectedEOF
	}

	n := min(len(p), r.limit-r.read)
	for i := range p[:n] {
		p[i] = 0
	}

	r.read += n

	return n, nil
}
