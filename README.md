
ldap-verify

This is a fork of go-ldap/ldap plus [a draft PR branch to add context](https://github.com/asuffield/ldap/tree/go-context), a couple more context-aware methods added, and a ton ripped out so no one else starts to depend on this.

The *only* intent is to be able to connect and test the most basic bind with a context, it's not adequate for a full authentication library or general ldap use.

