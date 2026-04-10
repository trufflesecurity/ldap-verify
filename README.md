# ldap-verify

A minimal, context-aware LDAP client library for Go, used by
[TruffleHog](https://github.com/trufflesecurity/trufflehog) to verify
discovered LDAP credentials.

## Origin

This is a fork of [go-ldap/ldap](https://github.com/go-ldap/ldap) (v3)
with [context support](https://github.com/asuffield/ldap/tree/go-context)
merged in. Most functionality has been deliberately removed to keep the
surface area small.

Previously hosted at `github.com/mariduv/ldap-verify`, this library was
moved under the `trufflesecurity` organization for provenance clarity.

## Scope

This library supports **only** the operations needed to test a simple
LDAP bind with context-based timeouts and cancellation:

- `DialURL` with `DialWithContext` and `DialWithTLSConfig` options
- `Bind` / `BindContext` (simple username+password)
- `StartTLS` for STARTTLS upgrade
- LDAP error codes and the `Error` type

It is **not** intended as a general-purpose LDAP library. For full LDAP
support, use [go-ldap/ldap](https://github.com/go-ldap/ldap).

## Usage

```go
import ldap "github.com/trufflesecurity/ldap-verify"

conn, err := ldap.DialURL("ldap://example.com:389", ldap.DialWithContext(ctx))
if err != nil {
    // handle error
}
defer conn.Close()

err = conn.BindContext(ctx, "cn=admin,dc=example,dc=com", "password")
if err != nil {
    // credentials are invalid or server is unreachable
}
```

## License

See [LICENSE](LICENSE).
