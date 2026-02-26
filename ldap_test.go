package ldap

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	// Debian has public servers but I don't want to prod them with tests
	// ldapServer  = "ldap://db.debian.org:389"
	// ldapsServer = "ldaps://db.debian.org:636"
	ldapServer  = "ldap://localhost:3893"
	ldapsServer = "ldaps://localhost:3894"
)

func TestDialTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
	defer cancel()

	l, err := DialURL("ldap://10.20.30.40:3893", DialWithContext(ctx))
	require.ErrorContains(t, err, "timeout")

	if l != nil {
		l.Close()
	}
}

func TestUnsecureDialURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	l, err := DialURL(ldapServer, DialWithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
}

func TestSecureDialURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	l, err := DialURL(ldapsServer, DialWithContext(ctx), DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
}

func TestStartTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	l, err := DialURL(ldapServer, DialWithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTLSConnectionState(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	l, err := DialURL(ldapServer, DialWithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}

	cs, ok := l.TLSConnectionState()
	if !ok {
		t.Errorf("TLSConnectionState returned ok == false; want true")
	}
	if cs.Version == 0 || !cs.HandshakeComplete {
		t.Errorf("ConnectionState = %#v; expected Version != 0 and HandshakeComplete = true", cs)
	}
}

func TestEscapeDN(t *testing.T) {
	tests := []struct {
		name string
		dn   string
		want string
	}{
		{name: "emptyString", dn: "", want: ""},
		{name: "comma", dn: "test,user", want: "test\\,user"},
		{name: "numberSign", dn: "#test#user#", want: "\\#test#user#"},
		{name: "backslash", dn: "\\test\\user\\", want: "\\\\test\\\\user\\\\"},
		{name: "whitespaces", dn: "  test user  ", want: "\\  test user \\ "},
		{name: "nullByte", dn: "\u0000te\x00st\x00user" + string(rune(0)), want: "\\00te\\00st\\00user\\00"},
		{name: "variousCharacters", dn: "test\"+,;<>\\-_user", want: "test\\\"\\+\\,\\;\\<\\>\\\\-_user"},
		{name: "multiByteRunes", dn: "test\u0391user ", want: "test\u0391user\\ "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EscapeDN(tt.dn); got != tt.want {
				t.Errorf("EscapeDN(%s) = %s, expected %s", tt.dn, got, tt.want)
			}
		})
	}
}

func TestBindContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	l, err := DialURL(ldapsServer, DialWithContext(ctx), DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	err = l.BindContext(ctx, "willfail", "hello")
	require.ErrorContains(t, err, "Invalid Credentials")

	err = l.BindContext(ctx, "hackers,dc=glauth,dc=com", "dogood")
	require.NoError(t, err)
}
