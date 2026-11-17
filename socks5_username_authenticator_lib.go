// Package socks5usernameauthenticatorlib implements the SOCKS5 username/password
// authentication sub-protocol defined in RFC 1929.
//
// The package is deliberately standalone: it does not perform the SOCKS5 method
// negotiation (RFC 1928) and it does not own the network connection. Callers
// hand it an io.Reader and io.Writer for the already-negotiated sub-negotiation
// stream, which makes the handler usable over TCP, TLS, or an in-memory pipe
// during tests.
package socks5usernameauthenticatorlib

import (
	"errors"
	"fmt"
	"io"
)

// Version is the sub-negotiation version byte required by RFC 1929.
// It is always 0x01 and is unrelated to the SOCKS5 version byte 0x05.
const Version byte = 0x01

// Status codes returned in the RFC 1929 reply.
const (
	StatusSuccess       byte = 0x00
	StatusFailure       byte = 0x01
	StatusNotSupported  byte = 0x02
)

// MaxUsernameLen and MaxPasswordLen are the largest lengths representable by
// the single length byte in the RFC 1929 wire format. Credentials longer than
// this cannot be transmitted, so the handler rejects them locally rather than
// silently truncating.
const (
	MaxUsernameLen = 255
	MaxPasswordLen = 255
)

// Sentinel errors. Callers can test with errors.Is.
var (
	// ErrBadVersion is returned when the client's sub-negotiation version byte
	// is not 0x01.
	ErrBadVersion = errors.New("socks5 username auth: unsupported sub-negotiation version")

	// ErrUsernameTooLong is returned when the supplied username exceeds 255 bytes.
	ErrUsernameTooLong = errors.New("socks5 username auth: username exceeds 255 bytes")

	// ErrPasswordTooLong is returned when the supplied password exceeds 255 bytes.
	ErrPasswordTooLong = errors.New("socks5 username auth: password exceeds 255 bytes")

	// ErrTruncated is returned when the peer closes the stream before sending a
	// complete request.
	ErrTruncated = errors.New("socks5 username auth: truncated request")

	// ErrAuthFailed is returned by Authenticate when the credentials supplied by
	// the client are rejected by the Verifier.
	ErrAuthFailed = errors.New("socks5 username auth: authentication failed")
)

// Verifier decides whether a username/password pair is acceptable.
//
// It is an interface rather than a func type so that implementations can carry
// state (a map, a database handle, a bcrypt cost) without the caller needing to
// wrap a closure. Implementations must not retain the byte slices after
// returning: the handler may reuse its read buffer.
type Verifier interface {
	Verify(username, password []byte) bool
}

// VerifierFunc adapts a plain function to the Verifier interface.
type VerifierFunc func(username, password []byte) bool

// Verify implements Verifier.
func (f VerifierFunc) Verify(username, password []byte) bool {
	return f(username, password)
}

// StaticVerifier is a Verifier that accepts exactly one username/password pair.
// It exists mainly for tests and for simple fixed-credential deployments.
//
// Comparison is byte-exact and constant-time with respect to length only; it is
// not a hardened cryptographic comparison and should not be used to compare
// password hashes.
type StaticVerifier struct {
	Username []byte
	Password []byte
}

// Verify implements Verifier.
func (v StaticVerifier) Verify(username, password []byte) bool {
	return equalBytes(v.Username, username) && equalBytes(v.Password, password)
}

// equalBytes reports whether a and b are byte-identical. It is written out
// rather than using bytes.Equal so the package has no import beyond io and
// errors, keeping the dependency surface at zero.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Authenticator performs the server side of the RFC 1929 sub-negotiation.
//
// The zero value is not usable; use New.
type Authenticator struct {
	verifier Verifier
}

// New returns an Authenticator that consults v for every handshake.
// It panics if v is nil, because a nil verifier would silently accept nothing
// and the failure would only surface at the first connection.
func New(v Verifier) *Authenticator {
	if v == nil {
		panic("socks5 username auth: nil verifier")
	}
	return &Authenticator{verifier: v}
}

// Authenticate runs one server-side sub-negotiation over r and w.
//
// On success it writes the 0x01 0x00 reply and returns nil. On a rejected
// credential it writes the 0x01 0x01 reply and returns ErrAuthFailed; the
// reply is written before the error so the client learns why it failed.
//
// Protocol errors (bad version byte, oversized fields, truncated input) are
// returned without writing a reply, because at that point we cannot trust the
// framing enough to emit a well-formed response.
func (a *Authenticator) Authenticate(r io.Reader, w io.Writer) error {
	username, password, err := readRequest(r)
	if err != nil {
		return err
	}

	if !a.verifier.Verify(username, password) {
		if werr := writeReply(w, StatusFailure); werr != nil {
			return werr
		}
		return ErrAuthFailed
	}

	return writeReply(w, StatusSuccess)
}

// readRequest parses the RFC 1929 request:
//
//	VER (1) | ULEN (1) | UNAME (ULEN) | PLEN (1) | PASSWD (PLEN)
//
// It reads the whole request into a fresh buffer so the returned slices are
// stable for the caller. The maximum request is 1+1+255+1+255 = 513 bytes,
// so pre-sizing the buffer avoids reallocation on the hot path.
func readRequest(r io.Reader) (username, password []byte, err error) {
	buf := make([]byte, 0, 513)

	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, nil, wrapTruncated(err)
	}
	if head[0] != Version {
		return nil, nil, fmt.Errorf("%w: got 0x%02x", ErrBadVersion, head[0])
	}

	ulen := int(head[1])
	buf = append(buf, head...)

	uname := make([]byte, ulen)
	if _, err := io.ReadFull(r, uname); err != nil {
		return nil, nil, wrapTruncated(err)
	}
	buf = append(buf, uname...)

	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, plenBuf); err != nil {
		return nil, nil, wrapTruncated(err)
	}
	buf = append(buf, plenBuf...)

	plen := int(plenBuf[0])
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(r, passwd); err != nil {
		return nil, nil, wrapTruncated(err)
	}
	buf = append(buf, passwd...)

	// Copy out of buf so the returned slices do not alias each other's backing
	// array in a way that a future refactor could corrupt.
	user := make([]byte, ulen)
	copy(user, buf[2:2+ulen])
	pass := make([]byte, plen)
	copy(pass, buf[3+ulen:3+ulen+plen])
	return user, pass, nil
}

// wrapTruncated converts io.EOF and io.ErrUnexpectedEOF into ErrTruncated,
// preserving the original error via %w so callers that want the underlying
// cause can still reach it.
func wrapTruncated(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %v", ErrTruncated, err)
	}
	return err
}

// writeReply writes the RFC 1929 reply: VER (1) | STATUS (1).
func writeReply(w io.Writer, status byte) error {
	_, err := w.Write([]byte{Version, status})
	return err
}

// EncodeRequest builds the on-the-wire bytes for a client request.
//
// It is exported so tests and client-side code do not have to re-derive the
// framing, and so the length limits are enforced in exactly one place.
func EncodeRequest(username, password []byte) ([]byte, error) {
	if len(username) > MaxUsernameLen {
		return nil, ErrUsernameTooLong
	}
	if len(password) > MaxPasswordLen {
		return nil, ErrPasswordTooLong
	}
	out := make([]byte, 0, 3+len(username)+len(password))
	out = append(out, Version, byte(len(username)))
	out = append(out, username...)
	out = append(out, byte(len(password)))
	out = append(out, password...)
	return out, nil
}

// DecodeReply parses the RFC 1929 reply and returns the status byte.
//
// The status byte is returned even when it is non-zero, so callers can
// distinguish "server said no" from "server spoke gibberish".
func DecodeReply(reply []byte) (byte, error) {
	if len(reply) < 2 {
		return 0, fmt.Errorf("%w: reply is %d bytes", ErrTruncated, len(reply))
	}
	if reply[0] != Version {
		return 0, fmt.Errorf("%w: got 0x%02x", ErrBadVersion, reply[0])
	}
	return reply[1], nil
}
