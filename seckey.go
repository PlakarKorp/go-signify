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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ebfe/bcrypt_pbkdf"
)

// DefaultKDFRounds is what signify(1) uses for a passphrase-protected key.
const DefaultKDFRounds = 42

// SecretKey is a signify secret key, decrypted and ready to sign.
type SecretKey struct {
	KeyNum  KeyNum
	Key     ed25519.PrivateKey
	Comment string

	// Rounds is the bcrypt_pbkdf cost the key was stored with. Zero means
	// the key is unencrypted on disk, which is how signify supports
	// unattended signing.
	Rounds uint32

	salt [16]byte
}

// Encrypted reports whether the key needs a passphrase.
func (sk *SecretKey) Encrypted() bool {
	return sk.Rounds > 0
}

// GenerateKey creates a keypair. comment is stored in the public key file;
// the secret key's own comment is derived from it the way signify does.
func GenerateKey(comment string) (*PublicKey, *SecretKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	var keynum KeyNum
	if _, err := io.ReadFull(rand.Reader, keynum[:]); err != nil {
		return nil, nil, err
	}

	pk := &PublicKey{KeyNum: keynum, Key: pub, Comment: comment}
	sk := &SecretKey{KeyNum: keynum, Key: priv, Comment: comment}

	if _, err := io.ReadFull(rand.Reader, sk.salt[:]); err != nil {
		return nil, nil, err
	}

	return pk, sk, nil
}

// ParseSecretKey parses and decrypts a secret key file. passphrase is ignored
// for an unencrypted key.
func ParseSecretKey(data, passphrase []byte) (*SecretKey, error) {
	f, err := parseFile(data)
	if err != nil {
		return nil, err
	}

	if len(f.payload) != secretKeySize {
		return nil, fmt.Errorf("%w: secret key is %d bytes, want %d",
			ErrInvalidFormat, len(f.payload), secretKeySize)
	}

	if string(f.payload[2:4]) != kdfAlg {
		return nil, fmt.Errorf("%w: unsupported KDF", ErrUnsupportedAlgorithm)
	}

	sk := &SecretKey{Comment: f.comment}
	sk.Rounds = binary.BigEndian.Uint32(f.payload[4:8])
	copy(sk.salt[:], f.payload[8:24])

	checksum := f.payload[24:32]
	copy(sk.KeyNum[:], f.payload[32:40])

	key := make([]byte, ed25519.PrivateKeySize)
	copy(key, f.payload[40:])

	if sk.Rounds > 0 {
		if len(passphrase) == 0 {
			return nil, ErrWrongPassphrase
		}

		xorkey := bcrypt_pbkdf.Key(passphrase, sk.salt[:], int(sk.Rounds), len(key))
		for i := range key {
			key[i] ^= xorkey[i]
		}

		zero(xorkey)
	}

	// The checksum is what distinguishes a wrong passphrase from a corrupt
	// key. Without it we would hand back a key that produces signatures
	// verifying against nothing.
	digest := sha512.Sum512(key)
	if subtle.ConstantTimeCompare(checksum, digest[:8]) != 1 {
		zero(key)
		return nil, ErrWrongPassphrase
	}

	sk.Key = ed25519.PrivateKey(key)

	return sk, nil
}

// Marshal renders the secret key as a signify file, encrypting it with
// passphrase. An empty passphrase writes an unencrypted key (rounds 0), which
// signify(1) also accepts and which suits unattended signing.
func (sk *SecretKey) Marshal(passphrase []byte) ([]byte, error) {
	rounds := uint32(0)
	if len(passphrase) > 0 {
		rounds = DefaultKDFRounds
		if sk.Rounds > 0 {
			rounds = sk.Rounds
		}
	}

	key := make([]byte, ed25519.PrivateKeySize)
	copy(key, sk.Key)

	defer zero(key)

	digest := sha512.Sum512(key)

	if rounds > 0 {
		xorkey := bcrypt_pbkdf.Key(passphrase, sk.salt[:], int(rounds), len(key))
		for i := range key {
			key[i] ^= xorkey[i]
		}

		zero(xorkey)
	}

	payload := make([]byte, 0, secretKeySize)
	payload = append(payload, pkAlg...)
	payload = append(payload, kdfAlg...)
	payload = binary.BigEndian.AppendUint32(payload, rounds)
	payload = append(payload, sk.salt[:]...)
	payload = append(payload, digest[:8]...)
	payload = append(payload, sk.KeyNum[:]...)
	payload = append(payload, key...)

	return marshalFile(sk.Comment, payload, nil)
}

// Sign produces a detached signature over msg. comment is the signature file's
// comment; SignatureComment builds signify's conventional one.
func (sk *SecretKey) Sign(msg []byte, comment string) *Signature {
	return &Signature{
		KeyNum:  sk.KeyNum,
		Sig:     ed25519.Sign(sk.Key, msg),
		Comment: comment,
	}
}

// SignEmbedded produces a signature carrying msg, so the two cannot be
// separated.
func (sk *SecretKey) SignEmbedded(msg []byte, comment string) *Signature {
	sig := sk.Sign(msg, comment)
	sig.Message = msg

	return sig
}

// Public derives the public key.
func (sk *SecretKey) Public() *PublicKey {
	pub, _ := sk.Key.Public().(ed25519.PublicKey)

	return &PublicKey{KeyNum: sk.KeyNum, Key: pub, Comment: sk.Comment}
}

// SignatureComment builds the comment signify writes into a signature, naming
// the public key that verifies it: "verify with <name>.pub".
//
// Callers should pass a bare name. signify(1) derives it from the secret key
// path it was given, which leaks the layout of the signing host into every
// published signature.
func SignatureComment(name string) string {
	return verifyWith + name + ".pub"
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
