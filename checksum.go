/*
 * Copyright (c) 2026 Gilles Chehade <gilles@poolp.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package signify

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strings"
)

var (
	// ErrNoChecksum is returned when a checksum list has no entry for the
	// requested file.
	ErrNoChecksum = errors.New("signify: no checksum for file")

	// ErrDigestMismatch is returned when a file does not hash to its
	// recorded checksum.
	ErrDigestMismatch = errors.New("signify: checksum mismatch")

	// ErrMalformedChecksum is returned for a line that is not a checksum.
	ErrMalformedChecksum = errors.New("signify: malformed checksum line")
)

// Tagged (BSD) form, as written by OpenBSD sha256(1) and GNU sha256sum --tag.
var taggedLine = regexp.MustCompile(`^([A-Z0-9]+) \((.+)\) = ([0-9a-fA-F]+)$`)

// Untagged (GNU) form: "<hex>  <name>". Accepted on input for compatibility
// with sha256sum's default output; never written.
var untaggedLine = regexp.MustCompile(`^([0-9a-fA-F]+) [ *](.+)$`)

// Checksum is one entry of a checksum file.
type Checksum struct {
	Algorithm string
	Filename  string
	Digest    string
}

// hasher returns a hash for the entry's algorithm.
func (c Checksum) hasher() (hash.Hash, error) {
	switch strings.ToUpper(c.Algorithm) {
	case "SHA256":
		return sha256.New(), nil
	case "SHA512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("signify: unsupported algorithm %q", c.Algorithm)
	}
}

// String renders the entry in tagged form.
func (c Checksum) String() string {
	return fmt.Sprintf("%s (%s) = %s", c.Algorithm, c.Filename, c.Digest)
}

// Verify hashes rd and compares it against the entry.
func (c Checksum) Verify(rd io.Reader) error {
	h, err := c.hasher()
	if err != nil {
		return err
	}

	if _, err := io.Copy(h, rd); err != nil {
		return err
	}

	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, c.Digest) {
		return fmt.Errorf("%w: %s has %s, want %s",
			ErrDigestMismatch, c.Filename, got, c.Digest)
	}

	return nil
}

// ChecksumList is a parsed checksum file.
type ChecksumList []Checksum

// Find returns the entry for filename.
func (l ChecksumList) Find(filename string) (Checksum, error) {
	for _, c := range l {
		if c.Filename == filename {
			return c, nil
		}
	}

	return Checksum{}, fmt.Errorf("%w: %s", ErrNoChecksum, filename)
}

// Filenames lists every file the list covers, in order.
func (l ChecksumList) Filenames() []string {
	out := make([]string, 0, len(l))
	for _, c := range l {
		out = append(out, c.Filename)
	}

	return out
}

// String renders the list in tagged form, one entry per line.
func (l ChecksumList) String() string {
	var b strings.Builder

	for _, c := range l {
		b.WriteString(c.String())
		b.WriteString("\n")
	}

	return b.String()
}

// ParseChecksums parses a checksum file in either tagged or untagged form.
// Blank lines are skipped; any other unparseable line is an error, so a
// malformed file is never mistaken for one covering nothing.
func ParseChecksums(data []byte) (ChecksumList, error) {
	var list ChecksumList

	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}

		if m := taggedLine.FindStringSubmatch(line); m != nil {
			list = append(list, Checksum{
				Algorithm: m[1],
				Filename:  m[2],
				Digest:    strings.ToLower(m[3]),
			})
			continue
		}

		if m := untaggedLine.FindStringSubmatch(line); m != nil {
			list = append(list, Checksum{
				Algorithm: "SHA256",
				Filename:  m[2],
				Digest:    strings.ToLower(m[1]),
			})
			continue
		}

		return nil, fmt.Errorf("%w: line %d: %q", ErrMalformedChecksum, i+1, line)
	}

	return list, nil
}

// ChecksumFile builds a tagged SHA256 entry for a file read from rd.
func ChecksumFile(name string, rd io.Reader) (Checksum, error) {
	h := sha256.New()

	if _, err := io.Copy(h, rd); err != nil {
		return Checksum{}, err
	}

	return Checksum{
		Algorithm: "SHA256",
		Filename:  name,
		Digest:    hex.EncodeToString(h.Sum(nil)),
	}, nil
}

// VerifyChecksumList verifies a signed checksum list and returns it. This is
// the first half of signify -C: the signature is checked before any listed
// file is consulted, so callers always work from signed data.
//
// The list must be an embedded signature; a detached one carries no list.
func VerifyChecksumList(pk *PublicKey, sig *Signature) (ChecksumList, error) {
	msg, err := pk.VerifyEmbedded(sig)
	if err != nil {
		return nil, err
	}

	return ParseChecksums(msg)
}

// Opener resolves a filename from a checksum list to its contents. Callers
// supply one so this package never touches the filesystem itself.
type Opener func(filename string) (io.ReadCloser, error)

// CheckFiles verifies a signed checksum list, then checks each named file
// against it. With no names, every file in the list is checked.
//
// This is signify -C. Note that the filename is what binds a checksum to a
// file: a caller that resolves names loosely gives up that binding.
func CheckFiles(pk *PublicKey, sig *Signature, open Opener, names ...string) error {
	list, err := VerifyChecksumList(pk, sig)
	if err != nil {
		return err
	}

	if len(names) == 0 {
		names = list.Filenames()
	}

	for _, name := range names {
		entry, err := list.Find(name)
		if err != nil {
			return err
		}

		rd, err := open(name)
		if err != nil {
			return err
		}

		err = entry.Verify(rd)
		rd.Close()

		if err != nil {
			return err
		}
	}

	return nil
}
