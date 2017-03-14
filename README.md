# Golang library `etcpwdparse`

This library provides simple access to the entries in the `/etc/passwd` file.

It was made for programs that need to be able to pull home directories, user id's and the
like but do not want the cgo-dependence of the core `os/user` package.

The only real caveat is that it doesn't pull user entries from other sources like PAM or
LDAP since it only operates by reading the file on disk.

## Usage:

```
go get github.com/AstromechZA/etcpwdparse
```

```golang
// load the passwd entries
// err will be non-nill if there was an IO or parsing error while loading the file
cache, err := NewLoadedEtcPasswdCache()
if err != nil {
    panic(err)
}

// pull the home directory
// there will be an err if the user could not be found
homedir, err := cache.HomeDirForUsername("bob")
```

See the documentation at [godoc.org/github.com/AstromechZA/etcpwdparse](https://godoc.org/github.com/AstromechZA/etcpwdparse)
for more information.
