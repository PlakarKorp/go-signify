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

// Package signify implements OpenBSD signify(1): ed25519 signatures over
// whole files, in a format that is two lines of text.
//
// Files are wire-compatible with signify(1) in both directions, so signatures
// produced here verify with the OpenBSD tool and vice versa.
package signify

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	pkAlg  = "Ed"
	kdfAlg = "BK"

	keyNumLen  = 8
	commentHdr = "untrusted comment: "
	verifyWith = "verify with "

	// MaxCommentLen matches signify(1)'s own limit.
	MaxCommentLen = 1024

	publicKeySize = 2 + keyNumLen + ed25519.PublicKeySize
	signatureSize = 2 + keyNumLen + ed25519.SignatureSize
	secretKeySize = 2 + 2 + 4 + 16 + 8 + keyNumLen + ed25519.PrivateKeySize
)

var (
	// ErrInvalidFormat is returned for input that is not a signify file.
	ErrInvalidFormat = errors.New("signify: invalid format")

	// ErrUnsupportedAlgorithm is returned for a well-formed file that is
	// not ed25519. signify has only ever defined "Ed".
	ErrUnsupportedAlgorithm = errors.New("signify: unsupported algorithm")

	// ErrBadSignature is returned when a signature does not verify.
	ErrBadSignature = errors.New("signify: signature verification failed")

	// ErrKeyMismatch is returned when a signature was produced by a key
	// other than the one it was checked against.
	ErrKeyMismatch = errors.New("signify: signature was made with a different key")

	// ErrWrongPassphrase is returned when a secret key fails its checksum
	// after decryption.
	ErrWrongPassphrase = errors.New("signify: incorrect passphrase")

	// ErrCommentTooLong is returned for a comment at or beyond
	// MaxCommentLen.
	ErrCommentTooLong = errors.New("signify: comment too long")
)

// KeyNum identifies a keypair. It is generated with the key and copied into
// every signature that key makes, so a verifier can select the right key
// without being told which one to use.
type KeyNum [keyNumLen]byte

// String renders the key number in the base64 form signify uses.
func (k KeyNum) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// PublicKey is a signify public key.
type PublicKey struct {
	KeyNum  KeyNum
	Key     ed25519.PublicKey
	Comment string
}

// Signature is a signify signature. Message is non-nil for an embedded
// signature, which carries the signed content after the signature line.
type Signature struct {
	KeyNum  KeyNum
	Sig     []byte
	Comment string
	Message []byte
}

// Embedded reports whether the signature carries the message it covers.
func (s *Signature) Embedded() bool {
	return s.Message != nil
}

// file is the shared shape of every signify file: a comment line, one line of
// base64, and optionally a trailing message.
type file struct {
	comment string
	payload []byte
	message []byte
}

// parseFile splits a signify file into its parts.
func parseFile(data []byte) (*file, error) {
	lines := strings.SplitN(string(data), "\n", 3)
	if len(lines) < 2 {
		return nil, ErrInvalidFormat
	}

	if !strings.HasPrefix(lines[0], commentHdr) {
		return nil, fmt.Errorf("%w: missing comment header", ErrInvalidFormat)
	}

	comment := strings.TrimSuffix(strings.TrimPrefix(lines[0], commentHdr), "\r")
	if len(comment) >= MaxCommentLen {
		return nil, ErrCommentTooLong
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(lines[1], "\r"))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidFormat, err)
	}

	if len(payload) < 2 {
		return nil, fmt.Errorf("%w: payload too short", ErrInvalidFormat)
	}

	if string(payload[:2]) != pkAlg {
		return nil, ErrUnsupportedAlgorithm
	}

	f := &file{comment: comment, payload: payload}

	if len(lines) == 3 && lines[2] != "" {
		f.message = []byte(lines[2])
	}

	return f, nil
}

// marshalFile renders a signify file. msg is appended after the base64 line
// when non-nil, which is signify's embedded mode.
func marshalFile(comment string, payload, msg []byte) ([]byte, error) {
	if len(comment) >= MaxCommentLen {
		return nil, ErrCommentTooLong
	}

	out := commentHdr + comment + "\n" +
		base64.StdEncoding.EncodeToString(payload) + "\n"

	return append([]byte(out), msg...), nil
}

// ParsePublicKey parses a signify public key file.
func ParsePublicKey(data []byte) (*PublicKey, error) {
	f, err := parseFile(data)
	if err != nil {
		return nil, err
	}

	if len(f.payload) != publicKeySize {
		return nil, fmt.Errorf("%w: public key is %d bytes, want %d",
			ErrInvalidFormat, len(f.payload), publicKeySize)
	}

	pk := &PublicKey{Comment: f.comment}
	copy(pk.KeyNum[:], f.payload[2:2+keyNumLen])
	pk.Key = ed25519.PublicKey(f.payload[2+keyNumLen:])

	return pk, nil
}

// Marshal renders the public key as a signify file.
func (pk *PublicKey) Marshal() ([]byte, error) {
	payload := make([]byte, 0, publicKeySize)
	payload = append(payload, pkAlg...)
	payload = append(payload, pk.KeyNum[:]...)
	payload = append(payload, pk.Key...)

	return marshalFile(pk.Comment, payload, nil)
}

// ParseSignature parses a signify signature file, detached or embedded.
func ParseSignature(data []byte) (*Signature, error) {
	f, err := parseFile(data)
	if err != nil {
		return nil, err
	}

	if len(f.payload) != signatureSize {
		return nil, fmt.Errorf("%w: signature is %d bytes, want %d",
			ErrInvalidFormat, len(f.payload), signatureSize)
	}

	sig := &Signature{Comment: f.comment, Message: f.message}
	copy(sig.KeyNum[:], f.payload[2:2+keyNumLen])
	sig.Sig = f.payload[2+keyNumLen:]

	return sig, nil
}

// Marshal renders the signature as a signify file, embedding Message when it
// is set.
func (s *Signature) Marshal() ([]byte, error) {
	payload := make([]byte, 0, signatureSize)
	payload = append(payload, pkAlg...)
	payload = append(payload, s.KeyNum[:]...)
	payload = append(payload, s.Sig...)

	return marshalFile(s.Comment, payload, s.Message)
}

// Verify checks sig over msg. The key number is compared first, so a
// signature made by a different key is reported as such rather than as a
// verification failure: the two mean different things to a caller choosing
// among several trusted keys.
func (pk *PublicKey) Verify(msg []byte, sig *Signature) error {
	if pk.KeyNum != sig.KeyNum {
		return ErrKeyMismatch
	}

	if !ed25519.Verify(pk.Key, msg, sig.Sig) {
		return ErrBadSignature
	}

	return nil
}

// VerifyEmbedded checks an embedded signature against the message it carries,
// returning that message.
func (pk *PublicKey) VerifyEmbedded(sig *Signature) ([]byte, error) {
	if !sig.Embedded() {
		return nil, fmt.Errorf("%w: signature is detached", ErrInvalidFormat)
	}

	if err := pk.Verify(sig.Message, sig); err != nil {
		return nil, err
	}

	return sig.Message, nil
}
