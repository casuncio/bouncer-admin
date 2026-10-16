package auth_test

import (
	"strings"
	"testing"

	"github.com/casuncio/bouncer-admin/internal/auth"
)

func mustSessionCodec(t *testing.T, secret string) *auth.SessionCodec {
	t.Helper()

	codec, err := auth.NewSessionCodec(secret)
	if err != nil {
		t.Fatalf("NewSessionCodec(%q): %v", secret, err)
	}
	return codec
}

func TestNewSessionCodec_EmptySecret(t *testing.T) {
	if _, err := auth.NewSessionCodec(""); err == nil {
		t.Fatal(`NewSessionCodec("") error = nil, want failure`)
	}
}

func TestSessionCodec_RoundTrip(t *testing.T) {
	codec := mustSessionCodec(t, "test-secret")

	in := auth.TokenSet{
		IDToken:      "header.payload.signature",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
	}

	sealed, err := codec.Seal(in)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if sealed == "" {
		t.Fatal("Seal() returned an empty value")
	}
	if strings.ContainsAny(sealed, "+/=") {
		t.Errorf("Seal() = %q, want cookie-safe raw base64url", sealed)
	}

	out, err := codec.Open(sealed)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if out != in {
		t.Errorf("round trip = %+v, want %+v", out, in)
	}
}

func TestSessionCodec_RoundTripIDTokenOnly(t *testing.T) {
	codec := mustSessionCodec(t, "test-secret")

	sealed, err := codec.Seal(auth.TokenSet{IDToken: "header.payload.signature"})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	out, err := codec.Open(sealed)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if out.IDToken != "header.payload.signature" {
		t.Errorf("IDToken = %q, want header.payload.signature", out.IDToken)
	}
	if out.AccessToken != "" || out.RefreshToken != "" {
		t.Errorf("round trip = %+v, want empty access/refresh tokens", out)
	}
}

func TestSessionCodec_SealUniquePerCall(t *testing.T) {
	codec := mustSessionCodec(t, "test-secret")

	first, err := codec.Seal(auth.TokenSet{IDToken: "token"})
	if err != nil {
		t.Fatalf("first Seal() error = %v", err)
	}
	second, err := codec.Seal(auth.TokenSet{IDToken: "token"})
	if err != nil {
		t.Fatalf("second Seal() error = %v", err)
	}

	if first == second {
		t.Fatal("sealing the same token set twice produced identical values; nonce reuse")
	}
	for _, sealed := range []string{first, second} {
		if _, err := codec.Open(sealed); err != nil {
			t.Errorf("Open() error = %v", err)
		}
	}
}

func TestSessionCodec_OpenTampered(t *testing.T) {
	codec := mustSessionCodec(t, "test-secret")

	sealed, err := codec.Seal(auth.TokenSet{IDToken: "header.payload.signature"})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	// Replace the first base64 character with a different valid one so the
	// value still decodes and the GCM authentication is what fails.
	mutated := []byte(sealed)
	if mutated[0] == 'A' {
		mutated[0] = 'B'
	} else {
		mutated[0] = 'A'
	}

	tests := []struct {
		name  string
		value string
	}{
		{name: "mutated base64", value: string(mutated)},
		{name: "truncated value", value: sealed[:len(sealed)-4]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := codec.Open(tt.value); err == nil {
				t.Error("Open() error = nil, want tamper detection failure")
			}
		})
	}
}

func TestSessionCodec_OpenWrongKey(t *testing.T) {
	sealer := mustSessionCodec(t, "correct-secret")
	opener := mustSessionCodec(t, "different-secret")

	sealed, err := sealer.Seal(auth.TokenSet{IDToken: "token"})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	if _, err := opener.Open(sealed); err == nil {
		t.Error("Open() error = nil, want wrong-key failure")
	}
}

func TestSessionCodec_OpenInvalidValues(t *testing.T) {
	codec := mustSessionCodec(t, "test-secret")

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "invalid base64", value: "not!base64"},
		{name: "too short", value: "AAAA"},
		{name: "wrong size", value: strings.Repeat("A", 40)},
		{name: "raw JWT", value: "header.payload.signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := codec.Open(tt.value); err == nil {
				t.Errorf("Open(%q) error = nil, want failure", tt.value)
			}
		})
	}
}
