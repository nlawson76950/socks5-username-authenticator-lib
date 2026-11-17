# socks5-username-authenticator-lib

Implements the server side of the SOCKS5 username/password authentication sub-protocol (RFC 1929) as a standalone Go handshake handler.

## Usage

```go
package main

import (
	"log"
	"net"

	socks5usernameauthenticatorlib "socks5-username-authenticator-lib"
)

func main() {
	auth := socks5usernameauthenticatorlib.New(socks5usernameauthenticatorlib.StaticVerifier{
		Username: []byte("alice"),
		Password: []byte("hunter2"),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			defer c.Close()
			// The SOCKS5 method negotiation (RFC 1928) happens on c before
			// this point; this call covers only the RFC 1929 sub-negotiation.
			if err := auth.Authenticate(c, c); err != nil {
				log.Printf("auth failed: %v", err)
			}
		}(conn)
	}
}
```

## Why this exists

RFC 1928 method negotiation and RFC 1929 credential exchange are usually glued into a
single SOCKS5 server, which makes the credential check untestable without a live socket.
This package splits the sub-negotiation out: it takes an `io.Reader` and an `io.Writer`,
so the same code runs over TCP, TLS, or an in-memory `bytes.Buffer` in tests. The
trade-off is that the caller is responsible for the method negotiation and for deciding
what to do after a failed handshake; the package writes the failure reply and returns
`ErrAuthFailed` but does not close the connection itself.

## API

- `New(v Verifier) *Authenticator` — panics on a nil verifier, because a nil verifier
  would silently reject every connection and the bug would only appear at runtime.
- `(*Authenticator).Authenticate(r io.Reader, w io.Writer) error` — runs one handshake.
- `Verifier` — interface with `Verify(username, password []byte) bool`.
- `VerifierFunc` — adapts a plain function to `Verifier`.
- `StaticVerifier` — accepts exactly one username/password pair.
- `EncodeRequest(username, password []byte) ([]byte, error)` — client-side framing helper.
- `DecodeReply(reply []byte) (byte, error)` — parses the two-byte reply.
- Errors: `ErrBadVersion`, `ErrUsernameTooLong`, `ErrPasswordTooLong`, `ErrTruncated`,
  `ErrAuthFailed`. All are testable with `errors.Is`.
- Status constants: `StatusSuccess`, `StatusFailure`, `StatusNotSupported`.
- `Version`, `MaxUsernameLen`, `MaxPasswordLen`.

## The awkward edge

RFC 1929 puts the username and password lengths in single bytes, so the longest
credential is 255 bytes. `EncodeRequest` returns `ErrUsernameTooLong` or
`ErrPasswordTooLong` rather than truncating, and `Authenticate` trusts the length
byte it reads from the wire. If a peer sends a length byte of 0 the corresponding
credential is empty, which is a legal wire value — `StaticVerifier{}` will accept an
empty username and an empty password, so do not use it as a production credential
store. A truncated stream yields `ErrTruncated` and no reply is written, because at
that point the framing cannot be trusted enough to emit a well-formed response.
