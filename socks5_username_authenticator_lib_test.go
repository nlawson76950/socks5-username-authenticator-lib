package socks5usernameauthenticatorlib

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// newAuth builds an Authenticator with a single fixed credential pair.
func newAuth(t *testing.T, user, pass string) *Authenticator {
	t.Helper()
	return New(StaticVerifier{Username: []byte(user), Password: []byte(pass)})
}

// roundTrip encodes a request, feeds it through Authenticate, and returns the
// raw reply bytes along with the error.
func roundTrip(t *testing.T, a *Authenticator, user, pass string) ([]byte, error) {
	t.Helper()
	req, err := EncodeRequest([]byte(user), []byte(pass))
	if err != nil {
		t.Fatalf("EncodeRequest(%q, %q): %v", user, pass, err)
	}
	var out bytes.Buffer
	err = a.Authenticate(bytes.NewReader(req), &out)
	return out.Bytes(), err
}

func TestAuthenticateSuccess(t *testing.T) {
	a := newAuth(t, "alice", "hunter2")
	reply, err := roundTrip(t, a, "alice", "hunter2")
	if err != nil {
		t.Fatalf("Authenticate: unexpected error: %v", err)
	}
	want := []byte{Version, StatusSuccess}
	if !bytes.Equal(reply, want) {
		t.Fatalf("reply = % x, want % x", reply, want)
	}
}

func TestAuthenticateRejected(t *testing.T) {
	a := newAuth(t, "alice", "hunter2")
	reply, err := roundTrip(t, a, "alice", "wrong")
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
	want := []byte{Version, StatusFailure}
	if !bytes.Equal(reply, want) {
		t.Fatalf("reply = % x, want % x", reply, want)
	}
}

func TestAuthenticateWrongUsername(t *testing.T) {
	a := newAuth(t, "alice", "hunter2")
	_, err := roundTrip(t, a, "bob", "hunter2")
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
}

func TestAuthenticateBadVersion(t *testing.T) {
	a := newAuth(t, "alice", "hunter2")
	// Version 0x05 is the SOCKS5 version, not the sub-negotiation version.
	req := []byte{0x05, 0x05, 'a', 'l', 'i', 'c', 'e', 0x07, 'h', 'u', 'n', 't', 'e', 'r', '2'}
	var out bytes.Buffer
	err := a.Authenticate(bytes.NewReader(req), &out)
	if !errors.Is(err, ErrBadVersion) {
		t.Fatalf("err = %v, want ErrBadVersion", err)
	}
	if out.Len() != 0 {
		t.Fatalf("wrote %d bytes on protocol error, want 0", out.Len())
	}
}

func TestAuthenticateTruncated(t *testing.T) {
	a := newAuth(t, "alice", "hunter2")
	full, err := EncodeRequest([]byte("alice"), []byte("hunter2"))
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	// Drop the last byte so the password is one byte short.
	var out bytes.Buffer
	err = a.Authenticate(bytes.NewReader(full[:len(full)-1]), &out)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
	if out.Len() != 0 {
		t.Fatalf("wrote %d bytes on truncated input, want 0", out.Len())
	}
}

func TestAuthenticateEmptyStream(t *testing.T) {
	a := newAuth(t, "alice", "hunter2")
	var out bytes.Buffer
	err := a.Authenticate(strings.NewReader(""), &out)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
}

func TestAuthenticateEmptyCredentials(t *testing.T) {
	a := newAuth(t, "", "")
	reply, err := roundTrip(t, a, "", "")
	if err != nil {
		t.Fatalf("Authenticate: unexpected error: %v", err)
	}
	if !bytes.Equal(reply, []byte{Version, StatusSuccess}) {
		t.Fatalf("reply = % x", reply)
	}
}

func TestAuthenticateMaxLengthCredentials(t *testing.T) {
	user := strings.Repeat("u", MaxUsernameLen)
	pass := strings.Repeat("p", MaxPasswordLen)
	a := newAuth(t, user, pass)
	reply, err := roundTrip(t, a, user, pass)
	if err != nil {
		t.Fatalf("Authenticate: unexpected error: %v", err)
	}
	if !bytes.Equal(reply, []byte{Version, StatusSuccess}) {
		t.Fatalf("reply = % x", reply)
	}
}

func TestEncodeRequestTooLong(t *testing.T) {
	_, err := EncodeRequest([]byte(strings.Repeat("u", MaxUsernameLen+1)), []byte("p"))
	if !errors.Is(err, ErrUsernameTooLong) {
		t.Fatalf("err = %v, want ErrUsernameTooLong", err)
	}
	_, err = EncodeRequest([]byte("u"), []byte(strings.Repeat("p", MaxPasswordLen+1)))
	if !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("err = %v, want ErrPasswordTooLong", err)
	}
}

func TestEncodeRequestFraming(t *testing.T) {
	got, err := EncodeRequest([]byte("ab"), []byte("cde"))
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	want := []byte{0x01, 0x02, 'a', 'b', 0x03, 'c', 'd', 'e'}
	if !bytes.Equal(got, want) {
		t.Fatalf("got % x, want % x", got, want)
	}
}

func TestDecodeReply(t *testing.T) {
	status, err := DecodeReply([]byte{0x01, 0x00})
	if err != nil {
		t.Fatalf("DecodeReply: %v", err)
	}
	if status != StatusSuccess {
		t.Fatalf("status = 0x%02x, want 0x00", status)
	}

	status, err = DecodeReply([]byte{0x01, 0x01})
	if err != nil {
		t.Fatalf("DecodeReply: %v", err)
	}
	if status != StatusFailure {
		t.Fatalf("status = 0x%02x, want 0x01", status)
	}
}

func TestDecodeReplyErrors(t *testing.T) {
	if _, err := DecodeReply([]byte{0x01}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short reply err = %v, want ErrTruncated", err)
	}
	if _, err := DecodeReply([]byte{0x02, 0x00}); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("bad version err = %v, want ErrBadVersion", err)
	}
}

func TestNewPanicsOnNilVerifier(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New(nil) did not panic")
		}
	}()
	New(nil)
}

func TestVerifierFunc(t *testing.T) {
	a := New(VerifierFunc(func(u, p []byte) bool {
		return string(u) == "x" && string(p) == "y"
	}))
	reply, err := roundTrip(t, a, "x", "y")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !bytes.Equal(reply, []byte{Version, StatusSuccess}) {
		t.Fatalf("reply = % x", reply)
	}
}

func TestAuthenticateWriteError(t *testing.T) {
	a := newAuth(t, "alice", "hunter2")
	req, err := EncodeRequest([]byte("alice"), []byte("hunter2"))
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	werr := errors.New("write failed")
	err = a.Authenticate(bytes.NewReader(req), failingWriter{err: werr})
	if !errors.Is(err, werr) {
		t.Fatalf("err = %v, want %v", err, werr)
	}
}

// failingWriter always fails, so we can prove write errors are propagated.
type failingWriter struct{ err error }

func (f failingWriter) Write(p []byte) (int, error) { return 0, f.err }

var _ io.Writer = failingWriter{}
