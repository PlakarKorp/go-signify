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

package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	signify "github.com/PlakarKorp/go-signify"
	"golang.org/x/term"
)

const usage = `usage:
	signify -C [-q] -p pubkey -x sigfile [file ...]
	signify -G [-n] [-c comment] -p pubkey -s seckey
	signify -S [-e] [-x sigfile] -s seckey -m message
	signify -V [-eq] [-x sigfile] -p pubkey -m message
`

type options struct {
	check    bool
	generate bool
	sign     bool
	verify   bool

	embedded bool
	noPass   bool
	quiet    bool

	comment string
	pubkey  string
	seckey  string
	sigfile string
	message string
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	var opts options

	fs := flag.NewFlagSet("signify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }

	fs.BoolVar(&opts.check, "C", false, "verify a signed checksum list")
	fs.BoolVar(&opts.generate, "G", false, "generate a new key pair")
	fs.BoolVar(&opts.sign, "S", false, "sign a message")
	fs.BoolVar(&opts.verify, "V", false, "verify a message")

	fs.BoolVar(&opts.embedded, "e", false, "embed the message in the signature")
	fs.BoolVar(&opts.noPass, "n", false, "do not ask for a passphrase")
	fs.BoolVar(&opts.quiet, "q", false, "suppress informational output")

	fs.StringVar(&opts.comment, "c", "signify", "comment to add during key generation")
	fs.StringVar(&opts.pubkey, "p", "", "public key file")
	fs.StringVar(&opts.seckey, "s", "", "secret key file")
	fs.StringVar(&opts.sigfile, "x", "", "signature file")
	fs.StringVar(&opts.message, "m", "", "message file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	n := 0
	for _, mode := range []bool{opts.check, opts.generate, opts.sign, opts.verify} {
		if mode {
			n++
		}
	}

	if n != 1 {
		fmt.Fprint(stderr, usage)
		return errors.New("exactly one of -C, -G, -S or -V is required")
	}

	switch {
	case opts.generate:
		return doGenerate(&opts, stdin, stderr)
	case opts.sign:
		return doSign(&opts, stdin, stderr)
	case opts.verify:
		return doVerify(&opts, stdout)
	default:
		return doCheck(&opts, fs.Args(), stdout)
	}
}

// defaultSigfile mirrors signify(1): the signature for <msg> is <msg>.sig
// unless -x says otherwise.
func defaultSigfile(opts *options) string {
	if opts.sigfile != "" {
		return opts.sigfile
	}

	return opts.message + ".sig"
}

func doGenerate(opts *options, stdin io.Reader, stderr io.Writer) error {
	if opts.pubkey == "" || opts.seckey == "" {
		return errors.New("-G requires -p and -s")
	}

	var passphrase []byte

	if !opts.noPass {
		var err error
		if passphrase, err = readPassphrase(stdin, stderr, true); err != nil {
			return err
		}
	}

	pk, sk, err := signify.GenerateKey(opts.comment + " public key")
	if err != nil {
		return err
	}

	sk.Comment = opts.comment + " secret key"

	secdata, err := sk.Marshal(passphrase)
	if err != nil {
		return err
	}

	pubdata, err := pk.Marshal()
	if err != nil {
		return err
	}

	// The secret key is written first and with restrictive permissions:
	// a world-readable private key is worse than no key at all.
	if err := os.WriteFile(opts.seckey, secdata, 0600); err != nil {
		return err
	}

	return os.WriteFile(opts.pubkey, pubdata, 0644)
}

func doSign(opts *options, stdin io.Reader, stderr io.Writer) error {
	if opts.seckey == "" || opts.message == "" {
		return errors.New("-S requires -s and -m")
	}

	secdata, err := os.ReadFile(opts.seckey)
	if err != nil {
		return err
	}

	var passphrase []byte

	if encrypted, err := isEncrypted(secdata); err != nil {
		return err
	} else if encrypted {
		if passphrase, err = readPassphrase(stdin, stderr, false); err != nil {
			return err
		}
	}

	sk, err := signify.ParseSecretKey(secdata, passphrase)
	if err != nil {
		return err
	}

	msg, err := os.ReadFile(opts.message)
	if err != nil {
		return err
	}

	comment := signify.SignatureComment(
		strings.TrimSuffix(filepath.Base(opts.seckey), ".sec"))

	var sig *signify.Signature

	if opts.embedded {
		sig = sk.SignEmbedded(msg, comment)
	} else {
		sig = sk.Sign(msg, comment)
	}

	data, err := sig.Marshal()
	if err != nil {
		return err
	}

	return os.WriteFile(defaultSigfile(opts), data, 0644)
}

func doVerify(opts *options, stdout io.Writer) error {
	if opts.pubkey == "" {
		return errors.New("-V requires -p")
	}

	if opts.message == "" {
		return errors.New("-V requires -m")
	}

	pk, err := readPublicKey(opts.pubkey)
	if err != nil {
		return err
	}

	sigdata, err := os.ReadFile(defaultSigfile(opts))
	if err != nil {
		return err
	}

	sig, err := signify.ParseSignature(sigdata)
	if err != nil {
		return err
	}

	if opts.embedded {
		// With -e the message is extracted from the signature and
		// written to -m, so -m names an output rather than an input.
		msg, err := pk.VerifyEmbedded(sig)
		if err != nil {
			return err
		}

		if err := os.WriteFile(opts.message, msg, 0644); err != nil {
			return err
		}
	} else {
		msg, err := os.ReadFile(opts.message)
		if err != nil {
			return err
		}

		if err := pk.Verify(msg, sig); err != nil {
			return err
		}
	}

	if !opts.quiet {
		fmt.Fprintln(stdout, "Signature Verified")
	}

	return nil
}

func doCheck(opts *options, files []string, stdout io.Writer) error {
	if opts.pubkey == "" || opts.sigfile == "" {
		return errors.New("-C requires -p and -x")
	}

	pk, err := readPublicKey(opts.pubkey)
	if err != nil {
		return err
	}

	sigdata, err := os.ReadFile(opts.sigfile)
	if err != nil {
		return err
	}

	sig, err := signify.ParseSignature(sigdata)
	if err != nil {
		return err
	}

	// Checksum files name their entries relative to their own directory,
	// so files are resolved there rather than in the working directory.
	base := filepath.Dir(opts.sigfile)

	open := func(name string) (io.ReadCloser, error) {
		return os.Open(filepath.Join(base, name))
	}

	if err := signify.CheckFiles(pk, sig, open, files...); err != nil {
		return err
	}

	if !opts.quiet {
		list, err := signify.VerifyChecksumList(pk, sig)
		if err != nil {
			return err
		}

		names := files
		if len(names) == 0 {
			names = list.Filenames()
		}

		for _, name := range names {
			fmt.Fprintf(stdout, "%s: OK\n", name)
		}

		fmt.Fprintln(stdout, "Signature Verified")
	}

	return nil
}

func readPublicKey(path string) (*signify.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return signify.ParsePublicKey(data)
}

// isEncrypted reports whether a secret key needs a passphrase, without
// decrypting it.
func isEncrypted(data []byte) (bool, error) {
	sk, err := signify.ParseSecretKey(data, nil)
	if err != nil {
		if errors.Is(err, signify.ErrWrongPassphrase) {
			return true, nil
		}

		return false, err
	}

	return sk.Encrypted(), nil
}

// readPassphrase prompts on a terminal with echo off, and otherwise reads a
// line from stdin, matching signify(1) so it can be driven from a script.
func readPassphrase(stdin io.Reader, stderr io.Writer, confirm bool) ([]byte, error) {
	// One buffered reader across both prompts: a fresh one per prompt
	// would buffer past the first line and leave the confirmation
	// unreadable.
	var buf *bufio.Reader

	prompt := func(label string) ([]byte, error) {
		fmt.Fprint(stderr, label)

		if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			pass, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(stderr)

			return pass, err
		}

		if buf == nil {
			buf = bufio.NewReader(stdin)
		}

		line, err := buf.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			return nil, err
		}

		return bytes.TrimRight(line, "\r\n"), nil
	}

	pass, err := prompt("passphrase: ")
	if err != nil {
		return nil, err
	}

	if len(pass) == 0 {
		return nil, errors.New("please provide a passphrase")
	}

	if confirm {
		again, err := prompt("confirm passphrase: ")
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(pass, again) {
			return nil, errors.New("passwords don't match")
		}
	}

	return pass, nil
}
